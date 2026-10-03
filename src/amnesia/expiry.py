"""Forgetting and decay: the half of memory governance that gets skipped, and
the half that causes incidents.

Three triggers, each mapping to a real scenario:

  1. Time decay      -- cold memories are archived. Not deleted, but no longer
                        recalled. "Forgotten" is not the same as "deleted";
                        keeping the audit trail is often the point.
  2. Superseded fact -- when a new fact contradicts an old one, the old one is
                        superseded and a version chain is preserved. Overwriting
                        in place throws away "we used to believe ...", which is
                        frequently the most useful context you have.
  3. Deletion request -- GDPR / data-subject erasure. This one must be a real,
                        physical delete, and it must produce a receipt.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .audit import AuditLog
from .backend import MemoryBackend
from .models import MemoryItem, Principal, utcnow
from .policy import PolicyEngine


@dataclass
class SweepReport:
    """Result of one maintenance pass. Field names match the audit events, for easy reconciliation."""

    superseded: list[dict[str, str]] = field(default_factory=list)
    archived: list[str] = field(default_factory=list)
    retention_expired: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.superseded or self.archived or self.retention_expired)

    def to_dict(self) -> dict[str, Any]:
        return {
            "superseded": self.superseded,
            "archived": self.archived,
            "retention_expired": self.retention_expired,
            "counts": {
                "superseded": len(self.superseded),
                "archived": len(self.archived),
                "retention_expired": len(self.retention_expired),
            },
        }


class Maintenance:
    def __init__(self, store: MemoryBackend, policy: PolicyEngine, audit: AuditLog | Any):
        self.store = store
        self.policy = policy
        self.audit = audit

    def rebind(self, policy: PolicyEngine) -> None:
        """Point at a freshly loaded policy engine after a hot reload.

        The maintenance engine caches nothing about the policy, so swapping the
        reference is sufficient -- but it must not be forgotten, or deletions would
        keep being judged against the previous revision.
        """
        self.policy = policy

    # ---- 1. superseded fact ----

    def supersede_conflicts(self, tenant: str | None = None) -> list[dict[str, str]]:
        """Several active memories under one subject: newest wins, older ones are
        marked superseded. The version chain survives on purpose -- "we used to
        think the PTO allowance was 10 days" is real, useful history.
        """
        events: list[dict[str, str]] = []
        subjects = {
            (item.tenant, item.subject)
            for item in self.store.all_items(tenant)
            if item.subject and item.status == "active"
        }
        for item_tenant, subject in sorted(subjects):
            actives = self.store.active_by_subject(item_tenant, subject)
            if len(actives) < 2:
                continue
            newest = max(actives, key=lambda i: i.created_at)
            for old in actives:
                if old.id == newest.id:
                    continue
                self.store.update(old.id, status="superseded", superseded_by=newest.id)
                self.audit.record(
                    "memory.superseded",
                    memory_id=old.id,
                    superseded_by=newest.id,
                    subject=subject,
                    reason="Superseded by a newer fact; the old version is kept on the chain",
                )
                events.append({"old": old.id, "new": newest.id, "subject": subject})
        return events

    # ---- 2. time decay ----

    def archive_stale(
        self,
        *,
        tenant: str | None = None,
        stale_days: int = 180,
        now: datetime | None = None,
    ) -> list[str]:
        """Archive every active memory that has gone cold.

        Deliberately not restricted to memories that have a `subject`. An earlier version
        skipped those, which made subjectless memories immortal -- they accumulated
        forever, kept influencing recall, and never appeared in a retention report. A
        memory's right to decay should not depend on whether we happened to tag it.
        """
        now = now or utcnow()
        cutoff = now - timedelta(days=stale_days)
        archived: list[str] = []
        for item in self.store.all_items(tenant):
            if item.status != "active":
                continue
            reference = item.last_access or item.created_at
            if reference < cutoff:
                self.store.update(item.id, status="archived")
                archived.append(item.id)
                self.audit.record(
                    "memory.archived",
                    memory_id=item.id,
                    reason=f"Cold memory: untouched since {reference.date().isoformat()}",
                )
        return archived

    # ---- 3. deletion request ----

    def forget(
        self,
        *,
        principal: Principal,
        ids: Sequence[str] | None = None,
        subject: str | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        """Physically delete, and return a receipt suitable for a compliance file.

        Rule: scopes flagged `deletable` can be removed by their owner; everything
        else needs the admin role. A refused deletion is audited too -- "someone
        tried to erase this and could not" is a signal worth keeping.
        """
        targets = self._resolve_targets(principal.tenant, ids, subject)
        is_admin = principal.has_role("admin")

        if not targets:
            # Reporting success for a deletion that removed nothing would put a false
            # statement in a compliance file. Say so instead.
            self.audit.forget(
                principal=principal.id,
                tenant=principal.tenant,
                outcome="no_match",
                requested=0,
                reason=reason,
            )
            return {
                "deleted": False,
                "reason": "No memories matched the request",
                "blocked": [],
            }

        blocked = [
            item for item in targets if not is_admin and not self.policy.is_deletable(item.scope)
        ]
        if blocked:
            refusal = (
                "Not permitted to delete retention-protected scopes: "
                f"{sorted({i.scope for i in blocked})}; the admin role is required"
            )
            self.audit.forget(
                principal=principal.id,
                tenant=principal.tenant,
                outcome="denied",
                requested=len(targets),
                blocked=[{"memory_id": i.id, "scope": i.scope} for i in blocked],
                reason=reason,
                refusal_reason=refusal,
            )
            return {
                "deleted": False,
                "reason": refusal,
                "blocked": [{"memory_id": i.id, "scope": i.scope} for i in blocked],
            }

        # Take the proof before deleting. Reverse this order and the proof is
        # gone forever.
        proofs = [
            {
                "memory_id": item.id,
                "scope": item.scope,
                "content_sha256": hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
                "content_bytes": len(item.content.encode("utf-8")),
                "created_at": item.created_at.isoformat(),
            }
            for item in targets
        ]
        deleted_ids = [item.id for item in targets]
        self.store.delete(deleted_ids)

        receipt = {
            "deleted": True,
            "deleted_count": len(deleted_ids),
            "deleted_ids": deleted_ids,
            "proof": proofs,
            "requested_by": principal.id,
            "reason": reason,
            "ts": utcnow().isoformat(),
        }
        self.audit.forget(
            principal=principal.id,
            tenant=principal.tenant,
            outcome="deleted",
            **{k: receipt[k] for k in ("deleted_count", "deleted_ids", "proof", "reason")},
        )
        return receipt

    def _resolve_targets(
        self, tenant: str, ids: Sequence[str] | None, subject: str | None
    ) -> list[MemoryItem]:
        out: list[MemoryItem] = []
        for mid in ids or []:
            item = self.store.get(mid)
            if item and item.tenant == tenant:
                out.append(item)
        if subject:
            for item in self.store.all_items(tenant):
                if item.subject == subject and item not in out:
                    out.append(item)
        return out

    # ---- orchestration ----

    def sweep(
        self,
        *,
        tenant: str | None = None,
        stale_days: int = 180,
        now: datetime | None = None,
    ) -> SweepReport:
        """One maintenance pass: supersede, then expire, then archive.

        The order is deliberate. Retention expiry is checked before cold-memory
        archiving, because expiry is the stronger and more legally meaningful statement:
        a record that has passed its retention window should be recorded as such, not
        filed away as a generic old memory. Archiving first would also change its status,
        so the expiry branch would never see it and the retention number would silently
        under-report.
        """
        now = now or utcnow()
        report = SweepReport()
        report.superseded = self.supersede_conflicts(tenant)

        report.retention_expired = [
            item.id
            for item in self.store.all_items(tenant)
            if item.expires_at and item.expires_at <= now and item.status == "active"
        ]
        for mid in report.retention_expired:
            self.store.update(mid, status="expired")
            self.audit.record(
                "memory.retention_expired", memory_id=mid, reason="Retention window elapsed"
            )

        report.archived = self.archive_stale(tenant=tenant, stale_days=stale_days, now=now)
        self.audit.sweep(tenant=tenant, **report.to_dict()["counts"])
        return report
