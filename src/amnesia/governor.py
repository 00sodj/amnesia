"""Orchestration: wires the write gate, read gate, poisoning detection, store,
forgetting engine and audit log into one chain.

Five verbs, deliberately few:

    remember   write          recall   read        forget   forget
    sweep      maintain       reload   re-read the policy file
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .audit import AuditLog, PolicyStampedAudit
from .backend import InMemoryLedger, MemoryBackend, WriteAttemptLedger, resolve_ledger
from .errors import PolicyError
from .expiry import Maintenance
from .models import MemoryItem, Principal, iso, utcnow
from .poison import PoisonDetector
from .policy import PolicyEngine, diff_configs
from .store import MemoryStore
from .validation import validate_principal, validate_recall, validate_write

# Page size for the post_filter candidate scan, and the ceiling on how many pages we walk.
#
# Paging is here for correctness, not for memory. A single truncated window lets memories
# the caller is *not* cleared for crowd out memories the caller *is* cleared for, so
# post_filter silently returns fewer results than pre_filter for the same query and
# identity. That divergence was reproducible, and it contradicts the product's central
# claim that the two paths agree. Scanning in pages removes it.
CANDIDATE_LIMIT = 200
MAX_CANDIDATE_PAGES = 25


def _without_content(view: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop the content from a memory view, keeping everything that identifies it."""
    if view is None:
        return None
    return {k: v for k, v in view.items() if k != "content"}


class MemoryGovernor:
    def __init__(
        self,
        *,
        policy: PolicyEngine | None = None,
        policy_path: str | Path | None = None,
        db_path: str | Path = ":memory:",
        journal_mode: str = "auto",
        audit_path: str | Path = "audit/memory.jsonl",
        store: MemoryBackend | None = None,
        audit: AuditLog | None = None,
        detector: PoisonDetector | None = None,
    ):
        self.policy = policy or (
            PolicyEngine.from_yaml(policy_path) if policy_path else PolicyEngine()
        )
        self.store: MemoryBackend = store or MemoryStore(db_path, journal_mode=journal_mode)
        self.ledger: WriteAttemptLedger = resolve_ledger(self.store)
        # Every audit entry records the policy revision in force when it was written.
        # Without it, a historical decision cannot be tied to the permissions that
        # permitted it -- which is the question a review actually asks.
        self.audit = PolicyStampedAudit(
            audit or AuditLog(audit_path), lambda: self.policy.revision
        )
        # Discovered by attribute, like the optional ledger: a backend either offers the
        # combined insert or it does not.
        self._combined_write = callable(getattr(self.store, "add_with_attempt", None))
        self.maintenance = Maintenance(self.store, self.policy, self.audit)
        self.detector = detector or self._build_detector()
        # Fingerprint of a policy revision that failed to load, so a broken file is
        # reported once instead of on every single request.
        self._bad_fingerprint: str | None = None

        if isinstance(self.ledger, InMemoryLedger):
            # Say so out loud. An operator must be able to tell "no burst happened"
            # apart from "bursts are invisible on this backend".
            self.audit.record(
                "governance.degraded",
                component="write_attempt_ledger",
                reason=(
                    "backend does not implement WriteAttemptLedger; burst detection "
                    "is limited to this process lifetime"
                ),
            )

    # ----------------------------------------------------------------- policy

    def _build_detector(self) -> PoisonDetector:
        return PoisonDetector(
            self.policy.poison_config, backend=self.store, ledger=self.ledger
        )

    def maybe_reload_policy(self) -> dict[str, Any] | None:
        """Re-read the policy file if its content changed.

        Cheap -- one read plus a hash -- so it can run at the top of every write and
        read. A filesystem watch is the production answer for high throughput;
        correctness first, and this keeps the behaviour obvious.

        A permission change that leaves no trace is precisely the thing this
        project exists to prevent, so both fingerprints and a human-readable diff
        go into the audit stream.
        """
        path = self.policy.source_path
        if path is None or not Path(path).exists():
            return None

        text = Path(path).read_text(encoding="utf-8")
        fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if fingerprint == self.policy.fingerprint:
            return None
        if fingerprint == self._bad_fingerprint:
            # Same broken content we already reported. Keep serving on the last good
            # policy without flooding the audit log on every request.
            return None

        try:
            new_engine = PolicyEngine.from_yaml(path)
        except PolicyError as exc:
            # Refusing every subsequent request because someone saved a broken YAML
            # would turn a typo into an outage. Keep serving on the last known good
            # policy, and make the failure loud enough that it cannot be missed.
            self._bad_fingerprint = fingerprint
            self.audit.record(
                "policy.reload_failed",
                path=str(path),
                offending_sha256=fingerprint,
                active_sha256=self.policy.fingerprint,
                active_revision=self.policy.revision,
                error=str(exc),
            )
            return {
                "reloaded": False,
                "error": str(exc),
                "active_revision": self.policy.revision,
            }

        self._bad_fingerprint = None
        old_fingerprint = self.policy.fingerprint
        old_config = self.policy.config
        changes = diff_configs(old_config, new_engine.config)

        self.policy = new_engine
        self.maintenance.rebind(new_engine)
        self.detector = self._build_detector()

        event = self.audit.record(
            "policy.changed",
            path=str(path),
            revision=new_engine.revision,
            old_sha256=old_fingerprint,
            new_sha256=fingerprint,
            actor=os.environ.get("AMNESIA_POLICY_ACTOR", "unknown"),
            changes=changes,
        )
        return {
            "reloaded": True,
            "revision": new_engine.revision,
            "changes": changes,
            "audit": event,
        }

    # ------------------------------------------------------------------ write

    def remember(
        self,
        content: str,
        *,
        source: str,
        tenant: str,
        scope: str | None = None,
        owner: str = "",
        subject: str = "",
        confidence: float = 1.0,
        tags: Sequence[str] = (),
    ) -> dict[str, Any]:
        self.maybe_reload_policy()

        scope = self.policy.normalize_scope(scope)
        validate_write(
            content=content,
            source=source,
            tenant=tenant,
            scope=scope,
            subject=subject,
            owner=owner,
            confidence=confidence,
            tags=tags,
        )
        now = utcnow()

        decision = self.policy.evaluate_write(
            content=content, source=source, scope=scope, confidence=confidence
        )
        if not decision.allow:
            # The content never touches disk. Only a hash goes into the audit log,
            # enough to spot someone repeatedly trying to store the same credential
            # without ever recording it.
            self.ledger.record_attempt(
                tenant=tenant, subject=subject, source=source, scope=scope,
                outcome="rejected", now=now,
            )
            self.audit.write_decision(
                tenant=tenant,
                subject=subject,
                source=source,
                scope=scope,
                outcome="rejected",
                rule=decision.code,
                reason=decision.reason,
                flags=list(decision.flags),
                content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
            return {
                "stored": False,
                "scope": scope,
                "reason": decision.reason,
                "flags": list(decision.flags),
            }

        # Idempotency, checked before poisoning detection on purpose: a retry storm of
        # identical writes is an upstream loop, not an attack, and flagging it as one would
        # be a false positive on the detector that is supposed to be trusted most.
        final_content = decision.transformed or content
        duplicate = self._find_duplicate(tenant, subject, source, final_content)
        if duplicate is not None:
            self.ledger.record_attempt(
                tenant=tenant, subject=subject, source=source, scope=scope,
                outcome="duplicate", now=now,
            )
            self.audit.record(
                "memory.write_duplicate",
                memory_id=duplicate.id,
                tenant=tenant,
                subject=subject,
                source=source,
                scope=duplicate.scope,
                reason="Identical content, subject and source; already active",
            )
            return {
                "stored": True,
                "duplicate": True,
                "id": duplicate.id,
                "scope": duplicate.scope,
                "reason": "Already stored: identical content from the same source",
                "flags": [],
                "content": duplicate.content,
                "expires_at": iso(duplicate.expires_at),
            }

        # The gate above judges this one memory. Poisoning is a pattern, so it is
        # checked separately, against the attempt ledger and the existing facts.
        # Order matters: inspect before recording this attempt, so the count the
        # detector sees does not yet include it.
        report = self.detector.inspect(
            content=content,
            source=source,
            tenant=tenant,
            subject=subject,
            scope=scope,
            now=now,
        )
        verdict = self.policy.evaluate_poison(report)

        if not verdict.allow:
            self.ledger.record_attempt(
                tenant=tenant, subject=subject, source=source, scope=scope,
                outcome="poison_blocked", now=now,
            )
            self.audit.record(
                "memory.write_poison_blocked",
                tenant=tenant,
                subject=subject,
                source=source,
                scope=scope,
                rule=verdict.code,
                # `verdict.reason` embeds `report.reasons()`, which quotes the matched text --
                # a snippet of the very content being refused. The audit log is built to be
                # greppable and archivable, so it has weaker access controls than the store by
                # design and must not carry content. The full finding stays in the return
                # value, where the caller already had the content anyway.
                reason=report.audit_summary(),
                severity=report.highest_severity,
                kinds=list(report.kinds()),
                content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
            return {
                "stored": False,
                "scope": scope,
                "reason": verdict.reason,
                "flags": list(verdict.flags),
                "poison": report.to_dict(),
            }

        if not report.empty:
            self.audit.record(
                "memory.write_poison_flagged",
                tenant=tenant,
                subject=subject,
                source=source,
                scope=scope,
                severity=report.highest_severity,
                kinds=list(report.kinds()),
                # Content-free, for the same reason as the blocked path above.
                detail=report.audit_summary(),
            )

        item = MemoryItem(
            content=decision.transformed or content,
            source=source,
            tenant=tenant,
            scope=scope,
            owner=owner or source,
            subject=subject,
            confidence=confidence,
            # Poisoning tags ride on the memory itself, so a flagged write stays
            # discoverable long after the audit log has been archived.
            tags=tuple(tags) + verdict.flags,
            expires_at=self.policy.expires_at_for(scope),
        )
        # The memory and its attempt record describe one event. The reference store writes
        # them in one transaction, which halves the commits per write -- measured at 17
        # writes/second with two and 35 with one on this filesystem. A backend that does not
        # offer the combined insert falls back to two, which is correct but slower.
        if self._combined_write:
            self.store.add_with_attempt(  # type: ignore[attr-defined]
                item,
                tenant=tenant,
                subject=subject,
                source=source,
                scope=scope,
                outcome="stored",
                now=now,
            )
        else:
            self.store.add(item)
            self.ledger.record_attempt(
                tenant=tenant, subject=subject, source=source, scope=scope,
                outcome="stored", now=now,
            )
        self.audit.write_decision(
            memory_id=item.id,
            tenant=tenant,
            subject=subject,
            source=source,
            scope=scope,
            outcome="stored",
            # `rule` describes the decision that produced this outcome, so it is the write
            # gate's code here -- not the poisoning verdict's. Mixing the two made it
            # impossible to group stored writes by what actually happened to them
            # (notably: stored as-is versus stored after redaction).
            rule=decision.code,
            poison_code=verdict.code,
            reason=decision.reason,
            flags=list(decision.flags) + list(verdict.flags),
            expires_at=iso(item.expires_at),
        )

        result: dict[str, Any] = {
            "stored": True,
            "id": item.id,
            "scope": scope,
            "reason": decision.reason,
            "flags": list(decision.flags) + list(verdict.flags),
            "content": item.content,
            "expires_at": iso(item.expires_at),
        }
        if not report.empty:
            result["poison"] = report.to_dict()
        return result

    # ------------------------------------------------------------------- read

    def recall(
        self,
        query: str,
        *,
        principal: Principal,
        limit: int = 5,
        mode: str = "post_filter",
    ) -> dict[str, Any]:
        """Recall.

        Returns not only the results but also what was relevant yet withheld.
        Denial records carry id, scope and reason only -- never content. An audit
        trail has to prove the boundary held without copying protected material
        into the log.
        """
        self.maybe_reload_policy()
        validate_principal(principal)
        validate_recall(query=query, limit=limit, mode=mode)

        now = utcnow()
        rules = self.policy.config["read"]
        min_confidence = float(rules.get("min_confidence", 0.0))
        min_score = float(rules.get("min_score", 0.0))
        allowed_scopes = self.policy.readable_scopes(principal)

        if mode == "pre_filter":
            # The scope predicate is already in the query, so a single page of `limit`
            # rows is the whole answer: there is nothing to scan past.
            batches: Iterable[list[tuple[MemoryItem, float]]] = (
                self.store.search_allowed(
                    query,
                    tenant=principal.tenant,
                    allowed_scopes=allowed_scopes,
                    min_confidence=min_confidence,
                    now=now,
                    limit=limit,
                    min_score=min_score,
                ),
            )
        else:
            batches = self._candidate_pages(
                query,
                tenant=principal.tenant,
                min_confidence=min_confidence,
                min_score=min_score,
                now=now,
            )

        results: list[dict[str, Any]] = []
        denied: list[dict[str, Any]] = []
        evaluated = 0

        for batch in batches:
            evaluated += len(batch)
            for item, score in batch:
                decision = self.policy.evaluate_read(item, principal, now=now)
                if decision.allow:
                    view = item.public_view()
                    view["score"] = round(score, 4)
                    view["provenance"] = {
                        "source": item.source,
                        "written_at": iso(item.created_at),
                        "confidence": round(item.confidence, 2),
                    }
                    results.append(view)
                else:
                    denied.append(
                        {
                            "memory_id": item.id,
                            "scope": item.scope,
                            "owner": item.owner,
                            "rule": decision.code,
                            "reason": decision.reason,
                        }
                    )
            if len(results) >= limit:
                break

        results = results[:limit]

        self.audit.read_decision(
            principal=principal.id,
            tenant=principal.tenant,
            roles=list(principal.roles),
            # Recorded so a refusal caused by a typo'd role is distinguishable from one the
            # policy intended. Both look identical in the refusal reason.
            unknown_roles=self.policy.unknown_roles(principal),
            query=query,
            mode=mode,
            returned=[r["id"] for r in results],
            denied_count=len(denied),
            # Needed to compute a refusal *rate*. Counting refusals without knowing how
            # many candidates were examined says nothing: ten refusals out of twelve is
            # a different situation from ten out of ten thousand.
            candidates_evaluated=evaluated,
            # Pre-aggregated so the compliance report never has to parse prose.
            rules_fired=dict(Counter(d["rule"] for d in denied)),
        )
        for entry in denied:
            self.audit.recall_denied(
                principal=principal.id,
                tenant=principal.tenant,
                query=query,
                **entry,
            )

        self.store.touch([r["id"] for r in results], now)

        return {
            "query": query,
            "principal": {
                "id": principal.id,
                "roles": list(principal.roles),
                "clearance": self.policy.clearance_for(principal),
                "unknown_roles": self.policy.unknown_roles(principal),
            },
            "results": results,
            "denied_count": len(denied),
            "denied": denied,
        }

    def _find_duplicate(
        self, tenant: str, subject: str, source: str, content: str
    ) -> MemoryItem | None:
        """Idempotent ingestion: the same fact, from the same source, is a retry.

        Why this exists: re-running an ingest duplicated the fact and recall returned it
        twice. To an agent that is not just wasteful context, it looks like a broken
        system. Every ingestion pipeline retries; the store should absorb that.

        Two deliberate narrowings:

        * **A subject is required.** Providing one is the caller declaring "this is a fact
          about X", which makes re-asserting it idempotent. Without a subject the caller
          has made no such claim, so two identical notes stay two notes.
        * **The source must match.** The same claim arriving from a second source is
          corroboration, and silently collapsing it would destroy provenance.
        """
        if not subject:
            return None
        for existing in self.store.active_by_subject(tenant, subject):
            if existing.source == source and existing.content == content:
                return existing
        return None

    def _candidate_pages(
        self,
        query: str,
        *,
        tenant: str,
        min_confidence: float,
        min_score: float,
        now: Any,
    ) -> Iterable[list[tuple[MemoryItem, float]]]:
        """Yield successive pages of candidates until the corpus is exhausted.

        Walking pages rather than taking one truncated window is what keeps `post_filter`
        from under-returning relative to `pre_filter`. The stop condition is deliberately
        "the page was short", not "we have enough results": a full page that is entirely
        refused must not end the scan, which was the original bug.

        The page ceiling bounds worst-case work on a pathological query and reports itself
        as a degradation rather than failing quietly.
        """
        offset = 0
        for _ in range(MAX_CANDIDATE_PAGES):
            batch = self.store.search_candidates(
                query,
                tenant=tenant,
                min_confidence=min_confidence,
                now=now,
                limit=CANDIDATE_LIMIT,
                min_score=min_score,
                offset=offset,
            )
            if not batch:
                return
            yield batch
            if len(batch) < CANDIDATE_LIMIT:
                return
            offset += CANDIDATE_LIMIT

        self.audit.record(
            "governance.degraded",
            component="candidate_scan",
            reason=(
                f"stopped after {MAX_CANDIDATE_PAGES} pages of {CANDIDATE_LIMIT}; "
                "results may under-report on a query this dense"
            ),
        )

    # ----------------------------------------------------------------- forget

    def forget(
        self,
        *,
        principal: Principal,
        ids: Sequence[str] | None = None,
        subject: str | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        return self.maintenance.forget(
            principal=principal, ids=ids, subject=subject, reason=reason
        )

    def sweep(self, *, tenant: str | None = None, stale_days: int = 180) -> dict[str, Any]:
        return self.maintenance.sweep(tenant=tenant, stale_days=stale_days).to_dict()

    # ---------------------------------------------------------------- explain

    def explain(
        self, memory_id: str, *, principal: Principal | None = None
    ) -> dict[str, Any]:
        """The full lifecycle of one memory: who wrote it, who asked, who was refused.

        `principal` gates the **content**, and that is not optional decoration. Without a
        principal the lifecycle is still returned but the content is not, for the same reason
        `memory_flagged` withholds it: a surface with no caller identity cannot check
        clearance, so handing out content there is a read-gate bypass.

        That was a real bug. An employee correctly refused by `recall` could read the same
        memory through `explain` if it knew the id -- a twelve-character string that appears
        in logs and in other tool output. A security layer whose explanation endpoint is more
        permissive than the thing it explains is not a security layer.
        """
        item = self.store.get(memory_id)
        lifecycle = self.audit.for_memory(memory_id)
        denials = [e for e in lifecycle if e["event"] == "memory.recall_denied"]

        payload: dict[str, Any] = {
            "memory": item.public_view() if item else None,
            "status": item.status if item else "not_found",
            "superseded_by": item.superseded_by if item else None,
            "tags": list(item.tags) if item else [],
            "lifecycle": lifecycle,
            "denial_count": len(denials),
            "denied_to": sorted({e.get("principal") for e in denials}),
        }

        if item is None:
            payload["content_withheld"] = False
            payload["content_decision"] = "memory not found"
            return payload

        if principal is None:
            payload["memory"] = _without_content(payload["memory"])
            payload["content_withheld"] = True
            payload["content_decision"] = (
                "no caller identity was supplied, so clearance could not be checked"
            )
            return payload

        decision = self.policy.evaluate_read(item, principal)
        self.audit.record(
            "memory.explain",
            memory_id=memory_id,
            principal=principal.id,
            tenant=principal.tenant,
            roles=list(principal.roles),
            unknown_roles=self.policy.unknown_roles(principal),
            outcome="allowed" if decision.allow else decision.code,
        )
        if decision.allow:
            payload["content_withheld"] = False
            payload["content_decision"] = "allowed"
        else:
            payload["memory"] = _without_content(payload["memory"])
            payload["content_withheld"] = True
            payload["content_decision"] = decision.reason
        return payload

    def stats(self, tenant: str | None = None) -> dict[str, Any]:
        by_scope: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for item in self.store.all_items(tenant):
            by_scope[item.scope] = by_scope.get(item.scope, 0) + 1
            by_status[item.status] = by_status.get(item.status, 0) + 1
        return {
            "total": self.store.count(tenant),
            "by_scope": by_scope,
            "by_status": by_status,
            "policy_revision": self.policy.revision,
        }

    def close(self) -> None:
        self.store.close()
