"""MCP server: mount the governance layer in front of any MCP-capable agent client.

The deliberate design choice: Amnesia is not another memory store. It sits in
front of the one you already have. Projects like `hindsight` and `ai-memory`
handle "remember reliably"; Amnesia handles "remember the right things".

Run it:

    AMNESIA_POLICY=policies/default.yaml \\
    AMNESIA_DB=amnesia.db \\
    AMNESIA_AUDIT=audit/memory.jsonl \\
    python -m amnesia.server
"""

from __future__ import annotations

import os
import threading
from typing import Any

from .governor import MemoryGovernor
from .models import Principal
from .policy import resolve_policy_path

_governor: MemoryGovernor | None = None
_governor_lock = threading.Lock()


def get_governor() -> MemoryGovernor:
    """Lazy singleton, constructed under a lock.

    The lock is not decoration. An MCP client can issue several tool calls that the server
    dispatches concurrently, and without the lock each of them found `_governor is None` and
    built its own: several SQLite connections to one file, several audit-log handles
    appending to one file, several WAL setup passes racing each other.

    That surfaced as an intermittent `Error executing tool memory_recall` under repeated
    runs -- roughly one in four -- which is the worst kind of defect for a governance layer:
    rare, load-dependent, and invisible until it is not. Reproduced by calling this function
    from eight threads at once: eight governors were built, not one.
    """
    global _governor
    if _governor is None:
        with _governor_lock:
            if _governor is None:  # re-check inside the lock
                _governor = MemoryGovernor(
                    policy_path=resolve_policy_path(),
                    db_path=os.environ.get("AMNESIA_DB", "amnesia.db"),
                    journal_mode=os.environ.get("AMNESIA_JOURNAL_MODE", "auto"),
                    audit_path=os.environ.get("AMNESIA_AUDIT", "audit/memory.jsonl"),
                )
    return _governor


def principal_of(principal_id: str, tenant: str, roles: str = "employee") -> Principal:
    parsed = tuple(r.strip() for r in (roles or "employee").split(",") if r.strip())
    return Principal(id=principal_id, tenant=tenant, roles=parsed or ("employee",))


try:  # mcp >= 2.0: FastMCP was renamed to MCPServer
    from mcp.server import MCPServer as _Server  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[attr-defined,no-redef]
    except ImportError:  # server extra not installed
        _Server = None  # type: ignore[assignment,misc]

try:  # both 1.x and 2.x carry the hint types here
    from mcp.types import ToolAnnotations as _Annotations
except ImportError:  # pragma: no cover - an SDK too old to declare hints
    _Annotations = None  # type: ignore[assignment,misc]


def _declared(*, read_only: bool, destructive: bool, idempotent: bool) -> Any:
    """Build a full set of tool hints, always naming all four.

    Naming all four matters because omitting one is not neutral: the specification
    defaults `destructiveHint` to **true**, so a tool that declares nothing is presented
    to the host as possibly destructive. With every tool undeclared, a read and an
    irreversible delete reach the host looking identical -- and a host that cannot tell
    them apart either confirms everything, at which point the confirmations stop being
    read, or confirms nothing, at which point the one call that destroys data is treated
    as routine. `memory_forget` must not look like `memory_stats`.

    `openWorldHint` is false throughout: every tool operates on this process's own SQLite
    store and audit file, and none of them reaches an entity outside it.

    Returns None on an SDK too old to carry hints, which is a no-op -- `annotations=None`
    is the decorator's default and the server still starts.
    """
    if _Annotations is None:  # pragma: no cover - depends on the SDK version
        return None
    return _Annotations(
        read_only_hint=read_only,
        destructive_hint=destructive,
        idempotent_hint=idempotent,
        open_world_hint=False,
    )


# The three shapes a tool here can take. Each is a claim a test defends.
#
# `_READ` -- adds, alters and removes nothing. These tools do append an audit entry and
#   touch `last_access`, and neither is a change to what is stored or who may read it:
#   one is the record *of* the read, the other is the access bookkeeping retention later
#   acts on. `idempotentHint` is deliberately left false rather than claimed, because
#   that `last_access` write means repeating a read is not strictly without effect.
#
# `_ADDITIVE` -- `memory_write` inserts and nothing else. That is not a guess: `store.add`
#   is a plain insert, and the superseding of an older fact happens later, in `sweep`.
#   `idempotentHint` is true because repeat-writes of identical content under the same
#   subject and source are collapsed to one memory, which is checked by
#   `test_identical_write_from_the_same_source_is_a_duplicate`.
#
# `_MUTATING` -- can take a record away from `recall`: `sweep` marks older conflicting
#   facts `superseded` and cold ones `archived`, and `forget` deletes physically.
_READ = _declared(read_only=True, destructive=False, idempotent=False)
_ADDITIVE = _declared(read_only=False, destructive=False, idempotent=True)
_MUTATING = _declared(read_only=False, destructive=True, idempotent=False)


if _Server is not None:

    def _build_server() -> Any:
        """Construct the server, reporting our version to clients.

        Deferred import to keep the module import order obvious, and the try/except
        because the 1.x SDK has no `version` parameter while 2.x does.
        """
        from . import __version__

        try:
            return _Server("amnesia", version=__version__)
        except TypeError:  # pragma: no cover - mcp 1.x
            return _Server("amnesia")

    mcp = _build_server()

    @mcp.tool(annotations=_ADDITIVE)
    def memory_write(
        content: str,
        source: str,
        tenant: str,
        scope: str = "project",
        owner: str = "",
        subject: str = "",
        confidence: float = 1.0,
    ) -> dict[str, Any]:
        """Store a memory through the write gate.

        Credentials are rejected outright; personal data is redacted before storage.

        scope: personal | project | confidential | hr_only
        subject: used for fact-conflict detection. A newer memory under the same subject
                 supersedes the older one on the next maintenance pass (`memory_sweep`),
                 not at write time -- a write only ever adds.
        """
        return get_governor().remember(
            content,
            source=source,
            tenant=tenant,
            scope=scope,
            owner=owner,
            subject=subject,
            confidence=confidence,
        )

    @mcp.tool(annotations=_READ)
    def memory_recall(
        query: str,
        principal_id: str,
        tenant: str,
        roles: str = "employee",
        limit: int = 5,
    ) -> dict[str, Any]:
        """Recall memories, scoped to the identity of the caller.

        Returns `results` (what this principal may see) and `denied` (what was
        relevant but withheld). Denial records contain id, scope and reason only.
        Do not attempt to reconstruct withheld content from them.
        """
        return get_governor().recall(
            query, principal=principal_of(principal_id, tenant, roles), limit=limit
        )

    @mcp.tool(annotations=_MUTATING)
    def memory_forget(
        principal_id: str,
        tenant: str,
        roles: str = "employee",
        memory_ids: str = "",
        subject: str = "",
        reason: str = "",
    ) -> dict[str, Any]:
        """Delete memories on request (physical delete). Returns a compliance receipt.

        Deleting from confidential or hr_only scopes requires the admin role.
        """
        ids = [m.strip() for m in memory_ids.split(",") if m.strip()]
        return get_governor().forget(
            principal=principal_of(principal_id, tenant, roles),
            ids=ids or None,
            subject=subject or None,
            reason=reason,
        )

    @mcp.tool(annotations=_MUTATING)
    def memory_sweep(tenant: str = "", stale_days: int = 180) -> dict[str, Any]:
        """Maintenance pass: supersede conflicting facts, archive cold memories,
        expire memories past their retention window.

        This changes records that already exist -- superseded and archived memories stop
        coming back from `memory_recall`. Nothing is deleted, so the version chain stays
        readable through `memory_explain`.
        """
        return get_governor().sweep(tenant=tenant or None, stale_days=stale_days)

    @mcp.tool(annotations=_READ)
    def memory_explain(
        memory_id: str,
        principal_id: str = "",
        tenant: str = "",
        roles: str = "employee",
    ) -> dict[str, Any]:
        """Trace one memory's full lifecycle: who wrote it, who asked, who was refused.

        Supply `principal_id` and `tenant` to receive the content; it is then checked against
        the read gate exactly as `memory_recall` would. Without them the lifecycle is returned
        and the content is withheld, because this surface has no other way to know who is
        asking -- and an explanation endpoint more permissive than recall is a bypass.
        """
        principal = (
            principal_of(principal_id, tenant, roles) if principal_id and tenant else None
        )
        return get_governor().explain(memory_id, principal=principal)

    @mcp.tool(annotations=_READ)
    def memory_stats(tenant: str = "") -> dict[str, Any]:
        """Store overview: total count, distribution by scope and by status."""
        return get_governor().stats(tenant or None)

    @mcp.tool(annotations=_READ)
    def memory_audit_tail(n: int = 20) -> list[dict[str, Any]]:
        """Most recent n audit entries."""
        return get_governor().audit.tail(n)

    @mcp.tool(annotations=_READ)
    def memory_flagged(tenant: str = "") -> list[dict[str, Any]]:
        """Memories that were stored but tagged by poisoning detection.

        Returns metadata only -- id, scope, source, subject, tags, timestamp. Content is
        withheld deliberately: this tool has no caller identity to check against, so
        including it would let any agent read memories it is not cleared for through a
        tool meant for triage. Use `amnesia flagged --show-content` from a shell instead.
        """
        from .poison import flagged_memories

        return flagged_memories(get_governor().store, tenant or None)

    @mcp.tool(annotations=_READ)
    def memory_report(tenant: str = "", days: int = 30) -> dict[str, Any]:
        """Compliance report for a window: recalls, refusals, writes, poisoning,
        deletions and policy changes, aggregated from the audit stream."""
        from .report import build_report

        return build_report(get_governor(), tenant=tenant or None, window_days=days)

    @mcp.tool(annotations=_READ)
    def memory_verify() -> dict[str, Any]:
        """Check that governance is actually in force.

        A misconfigured governance layer fails silently -- every call succeeds and
        nothing is enforced. Warnings mean a guarantee is weaker than it looks.
        """
        from .diagnostics import run_checks, summarise

        return summarise(run_checks(get_governor()))

    @mcp.tool(annotations=_READ)
    def memory_policy(include_config: bool = False) -> dict[str, Any]:
        """The active policy's identity: revision, fingerprint and source path.

        `include_config` dumps the full policy. Useful for a human debugging a
        deployment; be aware it reveals the whole permission model.
        """
        governor = get_governor()
        payload: dict[str, Any] = {
            "revision": governor.policy.revision,
            "fingerprint": governor.policy.fingerprint,
            "source_path": str(governor.policy.source_path)
            if governor.policy.source_path
            else None,
        }
        if include_config:
            payload["config"] = governor.policy.config
        return payload


def main() -> None:
    if _Server is None:
        raise SystemExit(
            "MCP SDK not installed. Run:\n"
            "    pip install -e '.[server]'\n"
            "then start again with: python -m amnesia.server"
        )
    mcp.run()


if __name__ == "__main__":
    main()
