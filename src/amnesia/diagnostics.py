"""Deployment diagnostics.

A misconfigured governance layer fails silently: every call succeeds, an answer comes
back, and nothing is being enforced. `run_checks` is the answer to "is this actually
governed?" -- shared by the CLI and the MCP surface so the two can never disagree about
what a healthy deployment looks like.

Severity is deliberate. `fail` means a guarantee is broken. `warn` means a guarantee is
weaker than it looks, or a check cannot fire at all. A fresh install legitimately has
warnings -- no source trust has been declared yet -- and treating that as failure would
train operators to ignore this command.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str

    @property
    def healthy(self) -> bool:
        return self.status != FAIL

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


def run_checks(governor: Any) -> list[Check]:
    """Inspect a live governor. Reads state; changes nothing."""
    from .backend import InMemoryLedger, WriteAttemptLedger

    checks: list[Check] = []

    # 1. Is the policy a real file we can attribute changes to?
    if governor.policy.source_path is None:
        checks.append(
            Check(
                "policy source",
                WARN,
                f"running on the built-in defaults (revision={governor.policy.revision}); "
                "changes cannot be attributed to a file revision",
            )
        )
    elif governor.policy.fingerprint is None:
        checks.append(Check("policy source", FAIL, "policy has a path but no fingerprint"))
    else:
        checks.append(
            Check(
                "policy source",
                OK,
                f"revision={governor.policy.revision} "
                f"fingerprint={governor.policy.fingerprint[:12]}",
            )
        )

    # 2. Store integrity and index freshness.
    if hasattr(governor.store, "health"):
        health = governor.store.health()
        checks.append(
            Check(
                "store integrity",
                OK if health["integrity"] == "ok" else FAIL,
                f"integrity={health['integrity']} journal={health['journal_mode']} "
                f"schema=v{health['schema_version']}",
            )
        )
        checks.append(
            Check(
                "term index fresh",
                OK if health["index_fresh"] else FAIL,
                f"{health['indexed_terms']} indexed terms for {health['memories']} memories",
            )
        )
        # A guarantee relaxed at runtime is a warning, not a failure -- but silence about it
        # would make an unnoticed degradation look like a feature that was never there.
        for note in health.get("degradations", []):
            checks.append(Check("runtime degradation", WARN, note))

        # Warn only when the operator asked for something they did not get. Warning about the
        # default journal mode would fire on every healthy deployment, and a warning that
        # always fires is a warning nobody reads.
        requested = health.get("requested_journal_mode")
        if requested == "wal" and health["journal_mode"] != "wal":
            checks.append(
                Check(
                    "requested journal mode",
                    WARN,
                    f"WAL was requested but the store is running on "
                    f"{health['journal_mode']}; this filesystem may not support the "
                    "shared-memory file WAL needs",
                )
            )
        elif requested == "auto" and health["journal_mode"] == "wal":
            checks.append(
                Check(
                    "write concurrency mode",
                    OK,
                    "journal mode is wal: readers do not block during a write",
                )
            )
    else:
        checks.append(
            Check("store integrity", WARN, f"{type(governor.store).__name__} exposes no health()")
        )

    # 2b. The audit hash chain. This is the check that turns "we record everything" into a claim
    # someone else can test: the log names where it was altered, not merely that it exists.
    # A FAIL here means the file on disk disagrees with its own hashes, which is not something an
    # operator should ever see without being told plainly.
    # Three levels, not two. `intact` is OK; `partial` — chained entries verified, but some
    # entries predate chaining or could not be parsed — is a WARNING, because a log that cannot
    # be fully verified is not the same as one that has been altered, but it is also not a clean
    # bill of health, and reporting it as OK would overstate the evidence.
    chain = governor.audit.chain_status()
    chain_level = {"intact": OK, "partial": WARN, "broken": FAIL}[chain.state]
    checks.append(Check("audit chain", chain_level, chain.describe()))

    # 3. Durability of the write-attempt ledger.
    durable = isinstance(governor.ledger, WriteAttemptLedger) and not isinstance(
        governor.ledger, InMemoryLedger
    )
    checks.append(
        Check(
            "write-attempt ledger",
            OK if durable else WARN,
            type(governor.ledger).__name__
            + ("" if durable else " -- burst detection resets when the process restarts"),
        )
    )

    # 4. Detection and the trust model it depends on.
    poison = governor.policy.poison_config
    checks.append(
        Check(
            "poisoning detection",
            OK if governor.detector.enabled else WARN,
            f"on_high={poison.get('on_high')}"
            + ("" if governor.detector.enabled else " -- disabled, writes are not inspected"),
        )
    )
    trusted = list(poison.get("trusted_sources") or [])
    checks.append(
        Check(
            "source trust declared",
            OK if trusted else WARN,
            ", ".join(trusted)
            or "trusted_sources is empty, so fact-flip and untrusted-source checks cannot fire",
        )
    )
    protected = list(poison.get("trusted_required_scopes") or [])
    checks.append(
        Check(
            "protected scopes declared",
            OK if protected else WARN,
            ", ".join(protected)
            or "trusted_required_scopes is empty; any source may write to any scope",
        )
    )

    # 5. Retention.
    retention = governor.policy.config["read"].get("deny_expired") is not False
    checks.append(
        Check("retention enforced", OK if retention else WARN, f"deny_expired={retention}")
    )

    return checks


def summarise(checks: list[Check]) -> dict[str, Any]:
    return {
        "healthy": all(c.healthy for c in checks),
        "failures": [c.name for c in checks if c.status == FAIL],
        "warnings": [c.name for c in checks if c.status == WARN],
        "checks": [c.to_dict() for c in checks],
    }
