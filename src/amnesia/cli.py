"""Operator CLI.

Governance is only real if an operator can inspect it without writing Python. The
commands here mirror the things a review actually asks for: what is stored, what was
withheld, who hit the boundary, what was flagged, what changed.

    amnesia stats
    amnesia report --days 30 --out report.md
    amnesia explain <memory_id>
    amnesia flagged
    amnesia sweep --stale-days 180
    amnesia audit --tail 20
    amnesia policy --show
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

from .errors import AmnesiaError
from .governor import MemoryGovernor
from .report import build_report, render_markdown


def _parse_when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if "T" in value or " " in value:
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return datetime.combine(date.fromisoformat(value), time.min, tzinfo=timezone.utc)
    except ValueError:
        # `from None` because the chained traceback would point at datetime internals;
        # the message already names the offending value.
        raise SystemExit(f"Unrecognised date {value!r}. Use YYYY-MM-DD or ISO 8601.") from None


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    else:
        print(payload)


def _governor(args: argparse.Namespace) -> MemoryGovernor:
    import os

    from .policy import resolve_policy_path

    return MemoryGovernor(
        # Same resolver as the MCP server, so both entry points enforce the same
        # permission model. They used to disagree: the server defaulted to the shipped
        # policy file, the CLI to the built-in defaults.
        policy_path=resolve_policy_path(args.policy),
        db_path=args.db,
        # "auto" steps down from WAL to the rollback journal if the filesystem cannot
        # sustain WAL's shared-memory file. Set AMNESIA_JOURNAL_MODE=wal to fail loudly
        # instead, or =delete to skip WAL entirely.
        journal_mode=os.environ.get("AMNESIA_JOURNAL_MODE", "auto"),
        audit_path=args.audit,
    )


# ------------------------------------------------------------------- commands


def _require_tenant(args: argparse.Namespace) -> str:
    if not args.tenant:
        raise SystemExit(
            "This command acts on behalf of a tenant, so --tenant is required.\n"
            "Example: amnesia --tenant acme ..."
        )
    return args.tenant


def cmd_remember(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    """Write one memory through the full gate.

    Exists so the core behaviour can be exercised from a shell. Without it, trying
    Amnesia meant either running the demo or writing Python -- which is a poor first
    experience for something whose whole point is being a layer you can put in front of
    another system.

    Exit code 0 means stored, 1 means refused. A refusal is not a malfunction, but a
    script needs to be able to branch on it.
    """
    result = gov.remember(
        args.content,
        source=args.source,
        tenant=_require_tenant(args),
        scope=args.scope,
        owner=args.owner,
        subject=args.subject,
        confidence=args.confidence,
        tags=tuple(args.tag or ()),
    )

    if args.json:
        _emit(result, True)
    elif result.get("duplicate"):
        print(f"duplicate  id={result['id']}  scope={result['scope']}")
        print("           identical content from the same source is already stored")
    elif result["stored"]:
        print(f"stored   id={result['id']}  scope={result['scope']}  expires={result['expires_at']}")
        print(f"         as: {result['content']}")
        if result.get("flags"):
            print(f"         flags: {', '.join(result['flags'])}")
    else:
        print(f"REFUSED  scope={result['scope']}")
        poison = result.get("poison")
        if poison:
            # The verdict's own reason already embeds every finding, so printing both repeats
            # the same long sentence twice. Lead with the severity and list the findings.
            print(f"         blocked by poisoning detection, {poison['highest_severity']}")
            for finding in poison["findings"]:
                print(f"         [{finding['severity']}] {finding['kind']}: {finding['detail']}")
        else:
            print(f"         {result['reason']}")
        if result.get("flags"):
            print(f"         flags: {', '.join(result['flags'])}")

    return 0 if result["stored"] else 1


def cmd_recall(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    """Ask a question as a given identity and see what comes back, and what does not.

    Always exits 0: being refused is a normal, correct outcome, not a failure. `remember`
    signals refusal through its exit code because a caller usually wants to know whether
    the write landed; here the answer itself is the result.
    """
    from .models import Principal

    tenant = _require_tenant(args)
    roles = tuple(r.strip() for r in (args.roles or "employee").split(",") if r.strip())
    principal = Principal(id=args.principal, tenant=tenant, roles=roles)

    view = gov.recall(args.query, principal=principal, limit=args.limit, mode=args.mode)

    if args.json:
        _emit(view, True)
        return 0

    who = view["principal"]
    print(f'query: "{view["query"]}"')
    print(f"as:    {who['id']} ({'/'.join(who['roles'])}, clearance {who['clearance']})")
    if who.get("unknown_roles"):
        # Fail-closed is right, but silence here sends an operator to debug the policy when
        # the actual cause is a typo in the role name.
        print(
            f"WARNING: the policy defines no such role(s): "
            f"{', '.join(who['unknown_roles'])} — they count as clearance 0"
        )
    print()
    print(f"returned {len(view['results'])}, withheld {view['denied_count']}")
    for row in view["results"]:
        print(f"  [{row['scope']}] {row['content']}")
        subject = f"  subject={row['subject']}" if row.get("subject") else ""
        print(
            f"      score={row['score']}  source={row['provenance']['source']}  "
            f"written={row['provenance']['written_at'][:10]}{subject}"
        )
    if view["denied"]:
        print()
        print("withheld (recorded in the audit log, content not logged):")
        for row in view["denied"]:
            print(f"  [{row['scope']}] {row['reason']}")
    return 0


def cmd_forget(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    """Deletion on request, and the receipt a compliance file needs.

    On the CLI for the same reason `remember` and `recall` are: physical deletion and its
    evidence are the parts of this product a reviewer will ask to see, and they should not
    require writing Python to exercise. A test asserts the refusal path never prints the
    content it refused.

    Exit 0 when something was deleted, 1 when the request was refused or matched nothing.
    """
    from .models import Principal

    tenant = _require_tenant(args)
    roles = tuple(r.strip() for r in (args.roles or "employee").split(",") if r.strip())
    principal = Principal(id=args.principal, tenant=tenant, roles=roles)

    ids = [args.id] if args.id else None
    if not ids and not args.subject:
        raise SystemExit("Say what to forget: pass --id <memory_id> or --subject <subject>.")

    receipt = gov.forget(
        principal=principal,
        ids=ids,
        subject=args.subject or None,
        reason=args.reason or "",
    )

    if args.json:
        _emit(receipt, True)
        return 0 if receipt.get("deleted") else 1

    if receipt.get("deleted"):
        print(f"deleted      {receipt['deleted_count']} record(s)")
        for proof in receipt["proof"]:
            print(
                f"  {proof['memory_id']}  scope={proof['scope']}  "
                f"{proof['content_bytes']} bytes  sha256={proof['content_sha256'][:16]}..."
            )
        print("             the row is gone; the audit log keeps this receipt, not the content")
        return 0

    print(f"REFUSED      {receipt['reason']}")
    for row in receipt.get("blocked", []):
        print(f"  {row['memory_id']}  scope={row['scope']}")
    return 1


def cmd_stats(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    stats = gov.stats(args.tenant or None)
    if args.json:
        _emit(stats, args.json)
        return 0
    print(f"memories    {stats['total']}")
    for label, key in (("by scope", "by_scope"), ("by status", "by_status")):
        items = stats[key]
        rendered = "  ".join(f"{k}={v}" for k, v in sorted(items.items())) or "(none)"
        print(f"  {label:<9} {rendered}")
    print(f"policy      revision {stats['policy_revision']}")
    return 0


def cmd_report(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    report = build_report(
        gov,
        tenant=args.tenant or None,
        since=_parse_when(args.since),
        until=_parse_when(args.until),
        window_days=args.days,
    )
    if args.json:
        _emit(report, True)
    else:
        markdown = render_markdown(report)
        if args.out:
            Path(args.out).write_text(markdown, encoding="utf-8")
            print(f"Report written to {args.out}")
        else:
            print(markdown)
    return 0


def cmd_explain(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    """The endpoint that answers "why did the agent say that?", so it has to read well.

    `--principal` is what unlocks the content, and it goes through the same read gate as a
    recall. Without it the lifecycle is shown and the content is withheld: an operator who
    supplies no identity is in the same position as the MCP surface, which also has no way to
    know who is asking. The CLI is still the convenient path, because passing `--principal`
    is one word -- but the gate is exercised, not skipped.
    """
    from .models import Principal

    principal = None
    if args.principal:
        roles = tuple(r.strip() for r in (args.roles or "employee").split(",") if r.strip())
        principal = Principal(
            id=args.principal, tenant=_require_tenant(args), roles=roles or ("employee",)
        )

    explained = gov.explain(args.memory_id, principal=principal)
    if args.json:
        _emit(explained, args.json)
        return 0

    memory = explained["memory"]
    if memory is None:
        print(f"No memory with id {args.memory_id}.")
        print("If it was deleted, the row is gone but its history is not:")
        for entry in explained["lifecycle"]:
            print(f"  {(entry.get('ts') or '')[:19]}Z  {entry.get('event')}")
        return 1

    print(f"memory       {memory['id']}")
    print(f"  scope      {memory['scope']}")
    print(f"  source     {memory['source']}  (written {memory['created_at'][:10]})")
    print(f"  subject    {memory['subject'] or '-'}")
    print(f"  confidence {memory['confidence']}")
    if explained["content_withheld"]:
        print(f"  content    [withheld: {explained['content_decision']}]")
        print("             pass --principal <id> to have it checked against the read gate")
    else:
        print(f"  content    {memory['content']}")
    if explained["tags"]:
        print(f"  tags       {', '.join(explained['tags'])}")
    print(f"status       {explained['status']}")
    if explained["superseded_by"]:
        print(f"             superseded by {explained['superseded_by']}; kept on the chain")
    print()
    print(
        f"lifecycle    {len(explained['lifecycle'])} events, "
        f"{explained['denial_count']} refusals"
    )
    if explained["denied_to"]:
        print(f"  refused to {', '.join(explained['denied_to'])}")
    for entry in explained["lifecycle"]:
        when = (entry.get("ts") or "")[:19]
        outcome = entry.get("outcome") or entry.get("rule") or ""
        print(f"  {when}Z  {entry.get('event', '?'):<26} {outcome}")
        reason = entry.get("reason") or entry.get("detail")
        if reason:
            print(f"{'':23}  {reason}")
    return 0


def cmd_flagged(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    """Memories that were stored but tagged by poisoning detection.

    Run from a shell by an operator who already has filesystem access to the store, so
    excerpts are included -- unlike the MCP tool, which has no caller identity to check.
    """
    from .poison import flagged_memories

    flagged = flagged_memories(gov.store, args.tenant or None, include_excerpt=False)
    if args.show_content:
        from .poison import flagged_memories as _with_excerpt

        flagged = _with_excerpt(gov.store, args.tenant or None, include_excerpt=True)

    if args.json:
        _emit(flagged, True)
    elif not flagged:
        print("No flagged memories.")
    else:
        print(f"{len(flagged)} flagged memor{'y' if len(flagged) == 1 else 'ies'}:")
        for row in flagged:
            print(
                f"  {row['id']}  [{row['scope']}]  {row['source']}  "
                f"{', '.join(row['tags'])}  {row['subject'] or '-'}"
            )
            if row.get("excerpt"):
                print(f"      {row['excerpt']}")
    return 0


def cmd_sweep(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    report = gov.sweep(tenant=args.tenant or None, stale_days=args.stale_days)
    if args.json:
        _emit(report, True)
        return 0
    counts = report["counts"]
    print(f"{counts['superseded']:>4}  facts superseded by a newer version")
    print(f"{counts['archived']:>4}  cold memories archived")
    print(f"{counts['retention_expired']:>4}  memories past their retention window")
    if report["superseded"]:
        print()
        # Kept short on purpose: the heading above already says what happened, and a longer
        # line wraps in a normal-width terminal and reads as a ragged list.
        for row in report["superseded"]:
            print(f"  {row['old']} -> {row['new']}  {row['subject']}")
    return 0


def cmd_audit(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    entries = gov.audit.tail(args.tail)
    if args.json:
        _emit(entries, True)
        return 0
    if not entries:
        print("No audit entries.")
        return 0
    for entry in entries:
        when = (entry.get("ts") or "")[:19]
        event = entry.get("event", "?")
        # Show the fields that make an entry identifiable at a glance, then the reason.
        detail_keys = (
            "outcome", "principal", "scope", "rule", "denied_count", "deleted_count",
        )
        detail = "  ".join(
            f"{k}={entry[k]}" for k in detail_keys if entry.get(k) not in (None, "")
        )
        revision = entry.get("policy_revision", "?")
        print(f"{when}Z  {event:<26} policy={revision:<14} {detail}")
        reason = entry.get("reason") or entry.get("detail")
        if reason:
            print(f"{'':21}  {reason}")
    return 0


def cmd_policy(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "revision": gov.policy.revision,
        "fingerprint": gov.policy.fingerprint,
        "source_path": str(gov.policy.source_path) if gov.policy.source_path else None,
    }
    if args.show:
        payload["config"] = gov.policy.config
    if args.json:
        _emit(payload, args.json)
        return 0

    print(f"revision     {payload['revision']}")
    print(f"fingerprint  {payload['fingerprint'] or '(built-in defaults, no file)'}")
    print(f"source       {payload['source_path'] or '(built-in defaults, no file)'}")
    if args.show:
        import yaml as _yaml

        print()
        print(_yaml.safe_dump(payload["config"], sort_keys=False, allow_unicode=True).rstrip())
    return 0


def cmd_verify(gov: MemoryGovernor, args: argparse.Namespace) -> int:
    """Pre-flight check that a deployment is actually governed.

    Worth having as its own command because a misconfigured governance layer fails
    silently: everything keeps working, and nothing is being enforced.
    """
    from .diagnostics import run_checks, summarise

    checks = run_checks(gov)
    if args.json:
        _emit(summarise(checks), True)
        return 0 if all(c.healthy for c in checks) else 1

    width = max(len(c.name) for c in checks)
    for check in checks:
        print(f"  [{check.status:>4}] {check.name.ljust(width)}  {check.detail}")

    summary = summarise(checks)
    if summary["failures"]:
        print(f"\n{len(summary['failures'])} failing check(s): {', '.join(summary['failures'])}")
        return 1
    if summary["warnings"]:
        print(
            f"\n{len(summary['warnings'])} warning(s): {', '.join(summary['warnings'])}\n"
            "Warnings mean a guarantee is weaker than it looks, not that anything broke."
        )
    else:
        print("\nAll checks passed.")
    return 0


# ---------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="amnesia",
        description="Inspect and operate an Amnesia governance layer.",
    )
    parser.add_argument("--version", action="version", version=f"amnesia {__version__}")
    parser.add_argument(
        "--db",
        default="amnesia.db",
        help="Memory store path (default: amnesia.db, honouring AMNESIA_DB)",
    )
    parser.add_argument(
        "--audit",
        default="audit/memory.jsonl",
        help="Audit log path (default: audit/memory.jsonl, honouring AMNESIA_AUDIT)",
    )
    parser.add_argument(
        "--policy",
        default=None,
        help="Policy file (default: $AMNESIA_POLICY, else the shipped default)",
    )
    parser.add_argument("--tenant", default="", help="Restrict to one tenant")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("stats", help="Store overview").set_defaults(func=cmd_stats)
    sub.add_parser("verify", help="Check that governance is actually in force").set_defaults(
        func=cmd_verify
    )
    flagged = sub.add_parser("flagged", help="Memories tagged by poisoning detection")
    flagged.add_argument(
        "--show-content",
        action="store_true",
        help="Include a short excerpt of each flagged memory",
    )
    flagged.set_defaults(func=cmd_flagged)

    remember = sub.add_parser("remember", help="Write one memory through the full gate")
    remember.add_argument("content")
    remember.add_argument("--source", required=True, help="Where it came from (mandatory)")
    remember.add_argument(
        "--scope",
        default="project",
        help="personal | project | confidential | hr_only (default: project)",
    )
    remember.add_argument("--owner", default="", help="Who the memory is about")
    remember.add_argument(
        "--subject", default="", help="Groups facts; a newer one supersedes the older"
    )
    remember.add_argument("--confidence", type=float, default=1.0)
    remember.add_argument("--tag", action="append", default=None, help="Repeatable")
    remember.set_defaults(func=cmd_remember)

    recall = sub.add_parser("recall", help="Ask a question as a given identity")
    recall.add_argument("query")
    recall.add_argument("--principal", required=True, help="The identity doing the asking")
    recall.add_argument(
        "--roles", default="employee", help="Comma-separated, e.g. employee,manager"
    )
    recall.add_argument("--limit", type=int, default=5)
    recall.add_argument(
        "--mode", default="post_filter", choices=["post_filter", "pre_filter"]
    )
    recall.set_defaults(func=cmd_recall)

    forget = sub.add_parser("forget", help="Delete memories on request, with a receipt")
    forget.add_argument("--id", default=None, help="A specific memory id")
    forget.add_argument("--subject", default="", help="Every memory under this subject")
    forget.add_argument("--principal", required=True, help="Who is making the request")
    forget.add_argument("--roles", default="employee", help="Comma-separated")
    forget.add_argument("--reason", default="", help="Recorded on the receipt")
    forget.set_defaults(func=cmd_forget)

    report = sub.add_parser("report", help="Compliance report")
    report.add_argument("--since", default=None, help="Window start (YYYY-MM-DD)")
    report.add_argument("--until", default=None, help="Window end (YYYY-MM-DD)")
    report.add_argument("--days", type=int, default=30, help="Window length if no --since")
    report.add_argument("--out", default=None, help="Write markdown to this file")
    report.set_defaults(func=cmd_report)

    explain = sub.add_parser("explain", help="Trace one memory's lifecycle")
    explain.add_argument("memory_id")
    explain.add_argument(
        "--principal",
        default="",
        help="Supply this to receive the content; it is checked against the read gate",
    )
    explain.add_argument("--roles", default="employee", help="Comma-separated")
    explain.set_defaults(func=cmd_explain)

    sweep = sub.add_parser("sweep", help="Run maintenance now")
    sweep.add_argument("--stale-days", type=int, default=180)
    sweep.set_defaults(func=cmd_sweep)

    audit = sub.add_parser("audit", help="Tail the audit stream")
    audit.add_argument("--tail", type=int, default=20)
    audit.set_defaults(func=cmd_audit)

    policy = sub.add_parser("policy", help="Show the active policy")
    policy.add_argument("--show", action="store_true", help="Include the full config")
    policy.set_defaults(func=cmd_policy)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Environment variables are the documented configuration path; explicit flags win.
    import os

    args.db = args.db if args.db != "amnesia.db" else os.environ.get("AMNESIA_DB", args.db)
    args.audit = (
        args.audit
        if args.audit != "audit/memory.jsonl"
        else os.environ.get("AMNESIA_AUDIT", args.audit)
    )

    governor: MemoryGovernor | None = None
    try:
        governor = _governor(args)
        return int(args.func(governor, args))
    except AmnesiaError as exc:
        # A user error must not look like a crash. argparse already exits 2 for bad flags, and
        # the product's own validation uses the same code so a script can tell "I called it
        # wrongly" (2) from "the gate refused me" (1) and "it worked" (0).
        #
        # This matters more than it sounds: a governance CLI that prints a stack trace when a
        # scope name is misspelled reads as broken, and an operator who thinks the tool is
        # broken stops using the tool.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if governor is not None:
            governor.close()


if __name__ == "__main__":
    sys.exit(main())
