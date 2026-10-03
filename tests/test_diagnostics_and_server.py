"""Deployment diagnostics and the MCP surface.

The MCP surface is the product's front door, so it gets its own tests rather than
relying on a manual handshake. The security property under test is that a triage tool
must not become a way to read memories the caller is not cleared for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from amnesia import MemoryGovernor, Principal
from amnesia.diagnostics import FAIL, OK, WARN, Check, run_checks, summarise

TENANT = "acme"
ALICE = Principal(id="alice", tenant=TENANT, roles=("employee",))
CAROL = Principal(id="carol", tenant=TENANT, roles=("hr",))

POLICY = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


@pytest.fixture()
def gov(tmp_path: Path):
    g = MemoryGovernor(
        policy_path=POLICY, db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl"
    )
    yield g
    g.close()


# ---------------------------------------------------------------- diagnostics


def test_checks_cover_every_guarantee_that_can_silently_degrade(tmp_path: Path):
    empty = MemoryGovernor(db_path=tmp_path / "e.db", audit_path=tmp_path / "e.jsonl")
    try:
        names = {check.name for check in run_checks(empty)}
        assert names == {
            "policy source",
            "store integrity",
            "term index fresh",
            "audit chain",
            "write-attempt ledger",
            "poisoning detection",
            "source trust declared",
            "protected scopes declared",
            "retention enforced",
        }
    finally:
        empty.close()


def test_a_fresh_default_deployment_produces_warnings_not_failures(tmp_path: Path):
    """Warnings are the honest state of a deployment that has not been configured."""
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        summary = summarise(run_checks(gov))
        assert summary["healthy"] is True
        assert summary["failures"] == []
        assert "source trust declared" in summary["warnings"]
        assert "policy source" in summary["warnings"]
    finally:
        gov.close()


def test_the_shipped_policy_clears_the_trust_warnings(gov: MemoryGovernor):
    summary = summarise(run_checks(gov))
    assert summary["failures"] == []
    assert "source trust declared" not in summary["warnings"]
    assert "protected scopes declared" not in summary["warnings"]
    assert summary["healthy"] is True


def test_a_stale_index_is_reported_as_a_failure(gov: MemoryGovernor):
    gov.remember("Falcon programme", source="wiki", tenant=TENANT, scope="project")
    gov.store._conn.execute("DELETE FROM terms")
    gov.store._conn.commit()

    summary = summarise(run_checks(gov))
    assert summary["healthy"] is False
    assert "term index fresh" in summary["failures"]


def test_a_backend_without_a_ledger_warns_about_burst_detection(tmp_path: Path):
    from _helpers import DictBackend

    gov = MemoryGovernor(
        store=DictBackend(), db_path=tmp_path / "unused.db", audit_path=tmp_path / "a.jsonl"
    )
    try:
        checks = {c.name: c for c in run_checks(gov)}
        assert checks["write-attempt ledger"].status == WARN
        assert "burst detection" in checks["write-attempt ledger"].detail
        assert checks["store integrity"].status == WARN  # no health() on this backend
    finally:
        gov.close()


def test_check_to_dict_is_serialisable():
    payload = Check("x", OK, "detail").to_dict()
    assert payload == {"name": "x", "status": "ok", "detail": "detail"}
    assert Check("x", FAIL, "").healthy is False
    assert Check("x", WARN, "").healthy is True


# ----------------------------------------------------------------- MCP surface


@pytest.fixture()
def server(tmp_path: Path, monkeypatch):
    """Bind the MCP tool functions to a temporary governor.

    The tools read a module-level singleton, which would otherwise write `amnesia.db`
    into the working directory during a test run.
    """
    mcp_server = pytest.importorskip("amnesia.server")
    if mcp_server._Server is None:  # pragma: no cover - depends on the extra
        pytest.skip("MCP SDK not installed")

    governor = MemoryGovernor(
        policy_path=POLICY, db_path=tmp_path / "mcp.db", audit_path=tmp_path / "mcp.jsonl"
    )
    monkeypatch.setattr(mcp_server, "_governor", governor)
    yield mcp_server
    governor.close()


def test_the_default_journal_mode_is_not_warned_about(tmp_path: Path):
    """Warning about the default would fire on every healthy deployment, and a warning that
    always fires is a warning nobody reads."""
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        gov.remember("A note.", source="wiki", tenant=TENANT, scope="project")
        names = {check.name: check for check in run_checks(gov)}
        assert gov.store.health()["journal_mode"] == "delete"
        assert "requested journal mode" not in names
        assert "runtime degradation" not in names
    finally:
        gov.close()


def test_wal_that_was_requested_and_achieved_is_not_warned_about(tmp_path: Path):
    gov = MemoryGovernor(
        db_path=tmp_path / "m.db",
        journal_mode="wal",
        audit_path=tmp_path / "a.jsonl",
    )
    try:
        assert gov.store.health()["journal_mode"] == "wal", "this filesystem supports WAL"
        names = {check.name for check in run_checks(gov)}
        assert "requested journal mode" not in names
        assert "runtime degradation" not in names
    finally:
        gov.close()


def test_a_requested_mode_that_was_not_achieved_is_a_warning(tmp_path: Path):
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        # Simulate the filesystem refusing: the store is on delete while WAL was asked for.
        gov.store.requested_journal_mode = "wal"
        checks = {check.name: check for check in run_checks(gov)}
        assert checks["requested journal mode"].status == WARN
    finally:
        gov.close()


def test_runtime_degradations_are_surfaced_as_warnings(tmp_path: Path):
    """A guarantee relaxed at runtime must be visible, or silence makes it look like a
    feature that was never there."""
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        gov.store.degradations.append("simulated: journal mode fell back")
        summary = summarise(run_checks(gov))
        assert any(
            check["name"] == "runtime degradation" for check in summary["checks"]
        )
        assert "runtime degradation" in summary["warnings"]
        assert summary["healthy"] is True, "a degradation is a warning, not a broken guarantee"
    finally:
        gov.close()


def test_server_without_env_uses_the_shipped_policy(tmp_path: Path, monkeypatch):
    """The CLI and the server must resolve the default policy the same way.

    They used to disagree, which meant the same product enforced two different permission
    models depending on which entry point you happened to start.
    """
    monkeypatch.delenv("AMNESIA_POLICY", raising=False)
    mcp_server = pytest.importorskip("amnesia.server")
    monkeypatch.setattr(mcp_server, "_governor", None)
    monkeypatch.setenv("AMNESIA_DB", str(tmp_path / "s.db"))
    monkeypatch.setenv("AMNESIA_AUDIT", str(tmp_path / "s.jsonl"))

    governor = mcp_server.get_governor()
    try:
        assert governor.policy.source_path is not None
        assert governor.policy.revision != "unversioned"
    finally:
        governor.close()


def test_server_env_policy_wins_over_the_shipped_default(tmp_path: Path, monkeypatch):
    custom = tmp_path / "custom.yaml"
    custom.write_text("version: 1\nrevision: 'from-env'\n", encoding="utf-8")
    mcp_server = pytest.importorskip("amnesia.server")
    monkeypatch.setattr(mcp_server, "_governor", None)
    monkeypatch.setenv("AMNESIA_POLICY", str(custom))
    monkeypatch.setenv("AMNESIA_DB", str(tmp_path / "s.db"))
    monkeypatch.setenv("AMNESIA_AUDIT", str(tmp_path / "s.jsonl"))

    governor = mcp_server.get_governor()
    try:
        assert governor.policy.revision == "from-env"
    finally:
        governor.close()


def test_get_governor_builds_exactly_one_instance_under_concurrency(
    tmp_path: Path, monkeypatch
):
    """Regression: the lazy singleton had no lock.

    Eight concurrent callers built eight governors -- eight SQLite connections to one file,
    eight handles appending to one audit log, eight WAL setup passes racing. It surfaced as
    an intermittent `Error executing tool memory_recall` under repeated runs.
    """
    import threading

    mcp_server = pytest.importorskip("amnesia.server")

    built: list[int] = []
    real = mcp_server.MemoryGovernor

    class Counting(real):  # type: ignore[misc, valid-type]
        def __init__(self, **kwargs):
            built.append(1)
            super().__init__(**kwargs)

    monkeypatch.setattr(mcp_server, "MemoryGovernor", Counting)
    monkeypatch.setattr(mcp_server, "_governor", None)
    monkeypatch.setenv("AMNESIA_POLICY", str(POLICY))
    monkeypatch.setenv("AMNESIA_DB", str(tmp_path / "race.db"))
    monkeypatch.setenv("AMNESIA_AUDIT", str(tmp_path / "race.jsonl"))

    barrier = threading.Barrier(8)

    def call() -> None:
        barrier.wait()
        mcp_server.get_governor()

    threads = [threading.Thread(target=call) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    try:
        assert len(built) == 1, f"{len(built)} governors constructed under concurrency"
    finally:
        mcp_server.get_governor().close()


def test_server_exposes_the_expected_tool_set(server):
    import asyncio

    tools = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert tools == {
        "memory_write",
        "memory_recall",
        "memory_forget",
        "memory_sweep",
        "memory_explain",
        "memory_stats",
        "memory_audit_tail",
        "memory_flagged",
        "memory_report",
        "memory_verify",
        "memory_policy",
    }


def test_mcp_tools_enforce_the_same_read_gate(server):
    server.memory_write(
        "Dana Whitfield's 2025 performance rating is B+.",
        source="hr-system",
        tenant=TENANT,
        scope="hr_only",
        owner="dana",
        subject="perf:dana",
    )
    as_employee = server.memory_recall("performance rating", "alice", TENANT, roles="employee")
    assert as_employee["results"] == []
    assert as_employee["denied"][0]["rule"] == "role_denied"

    as_hr = server.memory_recall("performance rating", "carol", TENANT, roles="hr")
    assert len(as_hr["results"]) == 1


def test_mcp_write_refuses_a_credential(server):
    result = server.memory_write(
        "OPENAI_API_KEY=sk-proj-9f2Kd8sLqW3mZx7Vb1Nc4Rt6Yh0Jp5Ga",
        source="paste",
        tenant=TENANT,
    )
    assert result["stored"] is False


def test_mcp_flagged_returns_metadata_without_content(server):
    """The security property: a triage tool must not become a read bypass.

    The MCP surface has no caller identity, so it cannot check clearance. Returning an
    excerpt would let any agent read memories it is not cleared for.
    """
    server.get_governor().remember(
        "Dana Whitfield's rating was adjusted upward at a manager's request.",
        source="scrape-bot",
        tenant=TENANT,
        scope="hr_only",
        owner="dana",
        subject="perf:dana:adjustment",
    )
    flagged = server.memory_flagged(TENANT)
    assert len(flagged) == 1
    assert "poison:untrusted_source" in flagged[0]["tags"]
    assert "excerpt" not in flagged[0]
    assert "content" not in flagged[0]
    assert "adjusted upward" not in str(flagged)


def test_mcp_report_returns_the_expected_shape(server):
    server.memory_write("A project note.", source="wiki", tenant=TENANT)
    server.memory_recall("project note", "alice", TENANT)
    report = server.memory_report(TENANT, days=7)
    assert report["headline"]["writes_stored"] == 1
    assert report["meta"]["tenant"] == TENANT


def test_mcp_verify_reports_health(server):
    payload = server.memory_verify()
    assert payload["healthy"] is True
    assert any(check["name"] == "store integrity" for check in payload["checks"])


def test_mcp_policy_hides_config_unless_asked(server):
    assert "config" not in server.memory_policy()
    assert "config" in server.memory_policy(include_config=True)


def test_mcp_explain_withholds_content_without_a_principal(server):
    """The MCP surface has no caller identity, so it cannot check clearance.

    This was a real bypass: `memory_explain` took only an id and returned content, so an
    agent correctly refused by `memory_recall` could read the same memory through the
    explanation endpoint. The tool now takes a principal, and without one withholds content.
    """
    stored = server.memory_write(
        "Dana Whitfield's 2025 performance rating is B+.",
        source="hr-system",
        tenant=TENANT,
        scope="hr_only",
        owner="dana",
        subject="perf:dana",
    )
    refused = server.memory_recall("performance rating", "alice", TENANT, roles="employee")
    assert refused["results"] == []

    anonymous = server.memory_explain(stored["id"])
    assert anonymous["content_withheld"] is True
    assert "B+" not in str(anonymous["memory"])

    # And supplying the identity applies the same gate as recall would.
    as_employee = server.memory_explain(
        stored["id"], principal_id="alice", tenant=TENANT, roles="employee"
    )
    assert as_employee["content_withheld"] is True

    as_hr = server.memory_explain(
        stored["id"], principal_id="carol", tenant=TENANT, roles="hr"
    )
    assert as_hr["content_withheld"] is False
    assert "B+" in as_hr["memory"]["content"]


def test_mcp_explain_traces_lifecycle(server):
    stored = server.memory_write(
        "Dana Whitfield's 2025 performance rating is B+.",
        source="hr-system",
        tenant=TENANT,
        scope="hr_only",
        owner="dana",
        subject="perf:dana",
    )
    server.memory_recall("performance rating", "alice", TENANT, roles="employee")
    explained = server.memory_explain(stored["id"])
    assert explained["denial_count"] == 1
    assert explained["denied_to"] == ["alice"]


def test_mcp_forget_returns_a_receipt(server):
    stored = server.memory_write(
        "The annual contract with Northwind is worth $2,400,000.",
        source="contract-db",
        tenant=TENANT,
        scope="confidential",
    )
    receipt = server.memory_forget(
        "dave", TENANT, roles="admin", memory_ids=stored["id"], reason="GDPR #1"
    )
    assert receipt["deleted"] is True
    assert len(receipt["proof"][0]["content_sha256"]) == 64


def test_mcp_sweep_and_stats(server):
    assert server.memory_sweep(TENANT)["counts"]["superseded"] == 0
    assert server.memory_stats(TENANT)["total"] == 0
    assert isinstance(server.memory_audit_tail(5), list)
