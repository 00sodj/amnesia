"""Compliance report export.

The audit log is the evidence; a report is the argument you make with it. Nobody
reads a JSONL stream in a review meeting, and "we have logs" is not an answer to
"show me that nobody accessed the HR records they should not have".

Design note: this module reads the audit stream rather than instrumenting the
governor. Anything that is not in the audit log is not reportable, which is the
correct pressure -- it keeps the audit trail honest instead of letting the report
know things the log does not.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any

from .models import parse_iso, utcnow
from .policy import UNVERSIONED

# Decision codes are already machine-readable; this is the human gloss used in the
# rendered report. Keeping the mapping here (not in policy.py) means adding a new code
# degrades to showing the raw code rather than silently vanishing.
#
# Write-gate codes are here as well as read-gate ones. Without them, every rejected write
# rendered as "unspecified", which is not something a reviewer can act on.
RULE_LABELS: dict[str, str] = {
    # read gate
    "tenant_mismatch": "cross-tenant access attempt",
    "role_denied": "explicit role bar",
    "insufficient_clearance": "insufficient clearance",
    "expired": "memory expired",
    "superseded": "memory superseded",
    "low_confidence": "below confidence floor",
    "not_active": "memory not active",
    "deleted": "memory deleted",
    # write gate
    "missing_source": "no provenance",
    "empty_content": "empty content",
    "blocked_content": "credentials or blocked content",
    "stored": "stored",
    "stored_redacted": "stored after redaction",
    # poisoning
    "clean": "no poisoning signal",
    "poison_ignored": "poisoning below threshold",
}

DEFAULT_WINDOW_DAYS = 30

_GLOBAL_EVENTS = {"policy.changed", "governance.degraded", "memory.sweep"}


def _label(code: str) -> str:
    """Human gloss for a decision code.

    An event carrying *no* code is labelled distinctly from one carrying an unfamiliar
    code. That matters because the audit log is append-only evidence: records written
    before machine-readable codes existed cannot be rewritten, and a report should say
    "no code was recorded" rather than lumping them in with codes this report does not
    recognise.
    """
    if not code:
        return "no rule code recorded"
    return RULE_LABELS.get(code, code)


def _in_window(
    entries: Iterable[dict[str, Any]],
    since: datetime,
    until: datetime,
    tenant: str | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries:
        ts = parse_iso(entry.get("ts"))
        if ts is None or not (since <= ts <= until):
            continue
        entry_tenant = entry.get("tenant")
        # Policy and degradation events are not tenant-scoped; dropping them when a
        # tenant filter is set would hide exactly the changes worth reviewing.
        if tenant and entry_tenant and entry_tenant != tenant:
            continue
        out.append(entry)
    return out


def _by(entries: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    return dict(Counter(str(e.get(key) or "unspecified") for e in entries).most_common())


def build_report(
    governor: Any,
    *,
    tenant: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> dict[str, Any]:
    """Aggregate one reporting window. `governor` is a MemoryGovernor."""
    generated_at = utcnow()
    until = until or generated_at
    since = since or (until - timedelta(days=window_days))

    all_entries = list(governor.audit.entries())
    # Entries whose timestamp cannot be read are excluded from every count -- and counted. The
    # audit log is deliberately a plain JSONL file that customers grep, diff and archive, so a
    # hand-edited line or a half-written one is a normal thing to find. Dropping those silently
    # would hide the case most worth reviewing; refusing to produce a report at all, which is
    # what used to happen, is worse than either.
    unreadable_timestamps = sum(1 for e in all_entries if parse_iso(e.get("ts")) is None)
    entries = _in_window(all_entries, since, until, tenant)
    by_event: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        by_event.setdefault(entry["event"], []).append(entry)

    writes = by_event.get("memory.write", [])
    reads = by_event.get("memory.read", [])
    denials = by_event.get("memory.recall_denied", [])
    poison_blocked = by_event.get("memory.write_poison_blocked", [])
    poison_flagged = by_event.get("memory.write_poison_flagged", [])
    deletions = by_event.get("memory.forget", [])
    policy_changes = by_event.get("policy.changed", [])
    degraded = by_event.get("governance.degraded", [])

    write_outcomes = _by(writes, "outcome")
    # Pass the raw code through, including an empty one. Substituting a placeholder here
    # would pre-empt `_label`, which is the only place that can tell "no code was
    # recorded" apart from "a code we do not recognise".
    rejection_codes = Counter(
        e.get("rule") or "" for e in writes if e.get("outcome") == "rejected"
    )
    # Derived from `flags`, not from `rule`. Redaction has always been recorded in flags;
    # the write-gate code only started carrying the stored/redacted distinction later, and
    # older records put the *poisoning* verdict in `rule` -- which rendered as "no poisoning
    # signal" underneath a heading about the write gate. Deriving from flags is correct for
    # every record ever written.
    stored_writes = [e for e in writes if e.get("outcome") == "stored"]
    stored_breakdown = Counter(
        "stored_redacted"
        if any(str(f).startswith("redacted:") for f in (e.get("flags") or []))
        else "stored"
        for e in stored_writes
    )
    duplicate_writes = by_event.get("memory.write_duplicate", [])
    denial_rules = Counter(e.get("rule") or "" for e in denials)

    approved_deletions = [e for e in deletions if e.get("outcome") == "deleted"]
    denied_deletions = [e for e in deletions if e.get("outcome") == "denied"]

    # Flagged-but-stored memories are the ones a human still has to look at: the
    # detector saw something but policy said "record it, do not block it".
    flagged_in_store = [
        {
            "id": item.id,
            "subject": item.subject,
            "scope": item.scope,
            "source": item.source,
            "tags": [t for t in item.tags if t.startswith("poison")],
        }
        for item in governor.store.all_items(tenant)
        if any(t.startswith("poison:") for t in item.tags)
    ]

    recall_attempts = len(reads)
    refusals = len(denials)
    # Refusals on their own say nothing. Ten refusals out of twelve candidates examined is
    # a different situation from ten out of ten thousand, and only the second suggests a
    # misconfigured permission.
    candidates_evaluated = sum(int(e.get("candidates_evaluated") or 0) for e in reads)

    # Two different findings, and conflating them made the report cry wolf. Several
    # *versioned* revisions means permissions genuinely changed. `unversioned` means the
    # decision was made with no policy file mounted at all -- a deployment inconsistency,
    # not a permission change, and the operator's fix is different.
    observed_revisions = sorted(
        {e["policy_revision"] for e in entries if e.get("policy_revision")}
    )
    versioned_revisions = [r for r in observed_revisions if r != UNVERSIONED]
    policy_changed = len(versioned_revisions) > 1
    policy_without_a_file = UNVERSIONED in observed_revisions
    # Some events governed by a policy file, others by the built-in defaults. Distinct
    # from a permission change, and distinct from a uniformly unmounted policy: the
    # operator's fix is to pass the flag consistently, not to review a permissions diff.
    policy_mixed = policy_without_a_file and bool(versioned_revisions)

    return {
        "meta": {
            "generated_at": generated_at.isoformat(),
            "window_start": since.isoformat(),
            "window_end": until.isoformat(),
            "tenant": tenant or "all",
            "policy_revision": governor.policy.revision,
            "policy_fingerprint": governor.policy.fingerprint,
            # Revisions that were actually in force for events in this window.
            "policy_revisions_observed": observed_revisions,
            "policy_versioned_revisions": versioned_revisions,
            "policy_changed_mid_window": policy_changed,
            "policy_without_a_file": policy_without_a_file,
            "policy_config_mixed": policy_mixed,
            "backend": type(governor.store).__name__,
            # Excluded from every window count above, and reported rather than swallowed.
            "unreadable_timestamps": unreadable_timestamps,
        },
        "headline": {
            "recall_attempts": recall_attempts,
            "refusals": refusals,
            "candidates_evaluated": candidates_evaluated,
            "refusal_rate": (
                round(refusals / candidates_evaluated, 4) if candidates_evaluated else 0.0
            ),
            "principals_refused": len({e.get("principal") for e in denials}),
            "writes_stored": write_outcomes.get("stored", 0),
            "writes_redacted": stored_breakdown.get("stored_redacted", 0),
            "writes_duplicate": len(duplicate_writes),
            "writes_rejected": write_outcomes.get("rejected", 0),
            "poison_blocked": len(poison_blocked),
            "poison_flagged": len(poison_flagged),
            "deletions_completed": len(approved_deletions),
            "deletions_refused": len(denied_deletions),
            "policy_changes": len(policy_changes),
        },
        "recall": {
            "attempts": recall_attempts,
            "refusals": refusals,
            "candidates_evaluated": candidates_evaluated,
            "refusal_rate": (
                round(refusals / candidates_evaluated, 4) if candidates_evaluated else 0.0
            ),
            "refusals_by_rule": {
                _label(k): v for k, v in denial_rules.most_common()
            },
            "refusals_by_scope": _by(denials, "scope"),
            "refusals_by_principal": _by(denials, "principal"),
        },
        "write": {
            "outcomes": write_outcomes,
            "stored_breakdown": {_label(k): v for k, v in stored_breakdown.items()},
            "redacted": stored_breakdown.get("stored_redacted", 0),
            "duplicates": len(duplicate_writes),
            "duplicate_sources": _by(duplicate_writes, "source"),
            "rejection_reasons": {_label(k): v for k, v in rejection_codes.most_common()},
        },
        "poisoning": {
            "blocked": len(poison_blocked),
            "flagged": len(poison_flagged),
            "blocked_by_kind": _by(
                [{"kind": k} for e in poison_blocked for k in e.get("kinds", [])], "kind"
            ),
            "flagged_by_kind": _by(
                [{"kind": k} for e in poison_flagged for k in e.get("kinds", [])], "kind"
            ),
            "blocked_sources": _by(poison_blocked, "source"),
            "flagged_still_in_store": flagged_in_store,
        },
        "forgetting": {
            "deletions_completed": len(approved_deletions),
            "deletions_refused": len(denied_deletions),
            "records_deleted": sum(int(e.get("deleted_count", 0)) for e in approved_deletions),
            "refused_deletions": [
                {
                    "principal": e.get("principal"),
                    "requested": e.get("requested"),
                    "blocked": e.get("blocked"),
                    "reason": e.get("refusal_reason") or e.get("reason"),
                    "justification": e.get("reason"),
                }
                for e in denied_deletions
            ],
            "superseded": len(by_event.get("memory.superseded", [])),
            "archived": len(by_event.get("memory.archived", [])),
            "retention_expired": len(by_event.get("memory.retention_expired", [])),
        },
        "policy": {
            "changes": [
                {
                    "ts": e.get("ts"),
                    "revision": e.get("revision"),
                    "actor": e.get("actor"),
                    "old_sha256": (e.get("old_sha256") or "")[:12],
                    "new_sha256": (e.get("new_sha256") or "")[:12],
                    "changes": e.get("changes", []),
                }
                for e in policy_changes
            ]
        },
        "degradations": [
            {"ts": e.get("ts"), "component": e.get("component"), "reason": e.get("reason")}
            for e in degraded
        ],
        "store": governor.stats(tenant),
    }


# ------------------------------------------------------------------ rendering


def _table(rows: list[tuple[str, Any]], headers: tuple[str, str]) -> str:
    if not rows:
        return "_(none)_\n"
    out = [f"| {headers[0]} | {headers[1]} |", "| --- | ---: |"]
    out += [f"| {k} | {v} |" for k, v in rows]
    return "\n".join(out) + "\n"


def render_markdown(report: Mapping[str, Any]) -> str:
    meta = report["meta"]
    head = report["headline"]
    recall = report["recall"]
    write = report["write"]
    poison = report["poisoning"]
    forget = report["forgetting"]
    store = report["store"]

    def counter_rows(counter: Mapping[str, Any], limit: int = 15) -> list[tuple[str, Any]]:
        return list(counter.items())[:limit]

    lines: list[str] = []
    lines.append("# Memory governance report")
    lines.append("")
    lines.append(
        f"**Tenant:** {meta['tenant']} | **Window:** {meta['window_start'][:10]} → "
        f"{meta['window_end'][:10]} | **Policy revision:** {meta['policy_revision']}"
    )
    lines.append(
        f"**Backend:** {meta['backend']} | **Generated:** {meta['generated_at'][:19]}Z"
    )
    unreadable = int(meta.get("unreadable_timestamps") or 0)
    if unreadable:
        lines.append(
            f"> **{unreadable} audit entr{'y' if unreadable == 1 else 'ies'} could not be "
            "placed in time** and are excluded from every count below. The log is a plain "
            "JSONL file by design, so a hand-edited or half-written line is expected; review "
            "them before treating these numbers as complete."
        )
    changed_mid_window = bool(meta.get("policy_changed_mid_window"))
    without_a_file = bool(meta.get("policy_without_a_file"))
    mixed = bool(meta.get("policy_config_mixed"))
    versioned_revisions = list(meta.get("policy_versioned_revisions") or [])

    if mixed:
        lines.append(
            "> **Mixed policy configuration.** Some events were governed by "
            + ", ".join(f"`{r}`" for r in versioned_revisions)
            + f", others by the built-in defaults (`{UNVERSIONED}`, no policy file "
            "mounted). The latter were not evaluated against your policy. Pass "
            "`--policy`, or set `AMNESIA_POLICY`, consistently."
        )
    elif changed_mid_window:
        lines.append(
            "> **Permissions changed during this window.** Events span revisions "
            + ", ".join(f"`{r}`" for r in versioned_revisions)
            + ", so they were not all governed by the same policy."
        )
    elif without_a_file:
        lines.append(
            f"> **No policy file was mounted.** `{UNVERSIONED}` means the engine used its "
            "built-in defaults. That is a valid configuration, but it is not the shipped "
            "policy, and permissions are whatever the defaults say."
        )
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append(
        _table(
            [
                ("Recall attempts", head["recall_attempts"]),
                ("Candidate memories examined", head["candidates_evaluated"]),
                ("Memories withheld", head["refusals"]),
                ("Refusal rate", f"{head['refusal_rate']:.2%}"),
                ("Principals refused at least once", head["principals_refused"]),
                ("Writes stored", head["writes_stored"]),
                ("Writes stored after redaction", head["writes_redacted"]),
                ("Writes recognised as duplicates", head["writes_duplicate"]),
                ("Writes rejected at the gate", head["writes_rejected"]),
                ("Writes blocked as poisoning", head["poison_blocked"]),
                ("Writes flagged as poisoning", head["poison_flagged"]),
                ("Deletion requests completed", head["deletions_completed"]),
                ("Deletion requests refused", head["deletions_refused"]),
                ("Policy changes", head["policy_changes"]),
            ],
            ("Metric", "Value"),
        )
    )

    lines.append("## Recall authorisation")
    lines.append("")
    lines.append(
        f"{recall['attempts']} recall operations examined "
        f"{recall['candidates_evaluated']} candidate memories and withheld "
        f"{recall['refusals']} ({recall['refusal_rate']:.2%})."
    )
    lines.append("")
    lines.append("**Withheld by rule**")
    lines.append("")
    lines.append(_table(counter_rows(recall["refusals_by_rule"]), ("Rule", "Count")))
    lines.append("**Withheld by scope**")
    lines.append("")
    lines.append(_table(counter_rows(recall["refusals_by_scope"]), ("Scope", "Count")))
    lines.append("**Principals that hit the boundary**")
    lines.append("")
    lines.append(
        _table(counter_rows(recall["refusals_by_principal"]), ("Principal", "Withheld"))
    )

    lines.append("## Write gate")
    lines.append("")
    lines.append(_table(counter_rows(write["outcomes"]), ("Outcome", "Count")))
    lines.append("**Stored writes, by what the gate did to them**")
    lines.append("")
    lines.append(_table(counter_rows(write["stored_breakdown"]), ("Outcome", "Count")))
    lines.append("**Rejection reasons**")
    lines.append("")
    lines.append(_table(counter_rows(write["rejection_reasons"]), ("Reason", "Count")))

    lines.append("## Memory poisoning")
    lines.append("")
    lines.append(
        _table(
            [
                ("Blocked", poison["blocked"]),
                ("Flagged (stored with tags)", poison["flagged"]),
                ("Flagged memories still in the store", len(poison["flagged_still_in_store"])),
            ],
            ("Metric", "Value"),
        )
    )
    lines.append("**Blocked by kind**")
    lines.append("")
    lines.append(_table(counter_rows(poison["blocked_by_kind"]), ("Kind", "Count")))
    if poison["flagged_still_in_store"]:
        lines.append("**Flagged memories requiring human review**")
        lines.append("")
        lines.append("| Memory | Subject | Scope | Source | Tags |")
        lines.append("| --- | --- | --- | --- | --- |")
        for row in poison["flagged_still_in_store"][:20]:
            lines.append(
                f"| `{row['id']}` | {row['subject'] or '—'} | {row['scope']} | "
                f"{row['source']} | {', '.join(row['tags'])} |"
            )
        lines.append("")

    lines.append("## Forgetting")
    lines.append("")
    lines.append(
        _table(
            [
                ("Deletion requests completed", forget["deletions_completed"]),
                ("Records physically deleted", forget["records_deleted"]),
                ("Deletion requests refused", forget["deletions_refused"]),
                ("Facts superseded", forget["superseded"]),
                ("Cold memories archived", forget["archived"]),
                ("Memories past retention", forget["retention_expired"]),
            ],
            ("Metric", "Value"),
        )
    )
    if forget["refused_deletions"]:
        lines.append("**Refused deletion requests**")
        lines.append("")
        for row in forget["refused_deletions"]:
            blocked = ", ".join(
                f"{b['memory_id']} ({b['scope']})" for b in (row["blocked"] or [])
            )
            lines.append(
                f"- `{row['principal']}` requested {row['requested']} record(s); "
                f"blocked on {blocked}"
            )
        lines.append("")

    lines.append("## Policy changes")
    lines.append("")
    if report["policy"]["changes"]:
        for change in report["policy"]["changes"]:
            lines.append(
                f"- **{change['ts'][:19]}Z** · revision `{change['revision']}` · "
                f"actor `{change['actor']}` · `{change['old_sha256']}` → `{change['new_sha256']}`"
            )
            for diff in change["changes"]:
                lines.append(f"  - {diff}")
    else:
        lines.append("_(no policy changes in this window)_")
    lines.append("")

    lines.append("## Store")
    lines.append("")
    lines.append(
        f"Total memories: **{store['total']}** | by scope: "
        + ", ".join(f"{k}={v}" for k, v in store["by_scope"].items())
        + " | by status: "
        + ", ".join(f"{k}={v}" for k, v in store["by_status"].items())
    )
    lines.append("")

    if report["degradations"]:
        lines.append("## Degradations")
        lines.append("")
        lines.append(
            "> The following guarantees were reduced at runtime. Absence of findings "
            "above may be an artefact of these, not evidence of good behaviour."
        )
        lines.append("")
        for row in report["degradations"]:
            lines.append(f"- **{row['component']}**: {row['reason']}")
        lines.append("")

    return "\n".join(lines)
