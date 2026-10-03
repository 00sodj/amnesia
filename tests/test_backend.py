"""The backend seam.

The README claims Amnesia sits in front of the memory store you already run. That
claim is only true if the store is swappable, so these tests drop in a foreign
backend that shares no code with `MemoryStore` and check that governance still holds.
"""

from __future__ import annotations

from pathlib import Path

from _helpers import DictBackend

from amnesia import (
    InMemoryLedger,
    MemoryBackend,
    MemoryGovernor,
    MemoryStore,
    Principal,
    WriteAttemptLedger,
    resolve_ledger,
)

TENANT = "acme"
ALICE = Principal(id="alice", tenant=TENANT, roles=("employee",))
CAROL = Principal(id="carol", tenant=TENANT, roles=("hr",))


def events(gov: MemoryGovernor) -> list[str]:
    return [e["event"] for e in gov.audit.entries()]


# ------------------------------------------------------------------ conformance


def test_reference_store_satisfies_the_protocol():
    store = MemoryStore(":memory:")
    try:
        assert isinstance(store, MemoryBackend)
        assert isinstance(store, WriteAttemptLedger)
    finally:
        store.close()


def test_foreign_backend_satisfies_the_protocol():
    assert isinstance(DictBackend(), MemoryBackend)


def test_foreign_backend_without_a_ledger_falls_back():
    ledger = resolve_ledger(DictBackend())
    assert isinstance(ledger, InMemoryLedger)
    assert not isinstance(DictBackend(), WriteAttemptLedger)


# ------------------------------------------------------- governing a foreign store


def test_governor_enforces_the_read_gate_over_a_foreign_backend(tmp_path: Path):
    gov = MemoryGovernor(
        store=DictBackend(),
        db_path=tmp_path / "unused.db",
        audit_path=tmp_path / "a.jsonl",
    )
    try:
        gov.remember(
            "Dana Whitfield's 2025 performance rating is B+.",
            source="hr-system",
            tenant=TENANT,
            scope="hr_only",
            owner="dana",
            subject="perf:dana",
        )

        as_employee = gov.recall("performance rating", principal=ALICE)
        assert as_employee["results"] == []
        assert as_employee["denied"][0]["rule"] == "role_denied"

        as_hr = gov.recall("performance rating", principal=CAROL)
        assert len(as_hr["results"]) == 1
    finally:
        gov.close()


def test_write_gate_runs_over_a_foreign_backend(tmp_path: Path):
    gov = MemoryGovernor(
        store=DictBackend(), db_path=tmp_path / "unused.db", audit_path=tmp_path / "a.jsonl"
    )
    try:
        rejected = gov.remember(
            "OPENAI_API_KEY=sk-proj-9f2Kd8sLqW3mZx7Vb1Nc4Rt6Yh0Jp5Ga",
            source="paste",
            tenant=TENANT,
            scope="project",
        )
        assert rejected["stored"] is False
        assert gov.store.count() == 0
    finally:
        gov.close()


def test_degradation_is_recorded_not_hidden(tmp_path: Path):
    """An operator must be able to tell "no burst" from "bursts are invisible"."""
    gov = MemoryGovernor(
        store=DictBackend(), db_path=tmp_path / "unused.db", audit_path=tmp_path / "a.jsonl"
    )
    try:
        assert "governance.degraded" in events(gov)
        record = next(e for e in gov.audit.entries() if e["event"] == "governance.degraded")
        assert record["component"] == "write_attempt_ledger"
        assert "burst detection" in record["reason"]
    finally:
        gov.close()


def test_no_degradation_event_for_the_reference_store(tmp_path: Path):
    gov = MemoryGovernor(
        store=MemoryStore(":memory:"),
        db_path=tmp_path / "unused.db",
        audit_path=tmp_path / "a.jsonl",
    )
    try:
        assert "governance.degraded" not in events(gov)
        assert gov.store.count_attempts_since(
            tenant=TENANT, subject="x", since=gov.policy.config and __import__("amnesia").utcnow()
        ) == 0
    finally:
        gov.close()


def test_in_memory_ledger_counts_and_isolates_by_subject():
    from amnesia import utcnow

    ledger = InMemoryLedger()
    now = utcnow()
    for subject in ("a", "a", "b"):
        ledger.record_attempt(
            tenant=TENANT, subject=subject, source="s", scope="project",
            outcome="stored", now=now,
        )
    epoch = now.replace(year=2000)
    assert ledger.count_attempts_since(tenant=TENANT, subject="a", since=epoch) == 2
    assert ledger.count_attempts_since(tenant=TENANT, subject="b", since=epoch) == 1
    assert ledger.count_attempts_since(tenant=TENANT, subject="c", since=epoch) == 0


def test_report_names_the_backend_in_use(tmp_path: Path):
    from amnesia import build_report

    gov = MemoryGovernor(
        store=DictBackend(), db_path=tmp_path / "unused.db", audit_path=tmp_path / "a.jsonl"
    )
    try:
        report = build_report(gov)
        assert report["meta"]["backend"] == "DictBackend"
        assert report["degradations"], "the report must surface reduced guarantees"
    finally:
        gov.close()
