"""Policy versioning, hot reload and change auditing.

The claim being tested: a permission change leaves a trace, and takes effect without
a restart. Both halves matter. Versioning without reload means the trace describes a
policy nobody is running; reload without versioning means a permission changed and
nobody can say when.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from amnesia import MemoryGovernor, PolicyEngine, PolicyError, Principal, diff_configs
from amnesia.policy import (
    UNVERSIONED,
    resolve_policy_path,
    shipped_policy_path,
)

TENANT = "acme"
ALICE = Principal(id="alice", tenant=TENANT, roles=("employee",))


def write_policy(path: Path, *, revision: str, employee_clearance: int) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "revision": revision,
                "roles": {
                    "employee": {"clearance": employee_clearance},
                    "admin": {"clearance": 4},
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


@pytest.fixture()
def gov(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    write_policy(policy_path, revision="1", employee_clearance=1)
    governor = MemoryGovernor(
        policy_path=policy_path,
        db_path=tmp_path / "m.db",
        audit_path=tmp_path / "a.jsonl",
    )
    yield governor, policy_path
    governor.close()


def seed_confidential(gov: MemoryGovernor) -> None:
    gov.remember(
        "The annual contract with Northwind is worth $2,400,000.",
        source="contract-db",
        tenant=TENANT,
        scope="confidential",
        subject="contract:northwind",
    )


# ------------------------------------------------------------------- fingerprints


def test_policy_records_its_source_and_fingerprint(tmp_path: Path):
    path = tmp_path / "p.yaml"
    write_policy(path, revision="7", employee_clearance=1)
    engine = PolicyEngine.from_yaml(path)
    assert engine.source_path == path
    assert engine.fingerprint and len(engine.fingerprint) == 64
    assert engine.revision == "7"


def test_in_memory_policy_has_no_fingerprint():
    engine = PolicyEngine()
    assert engine.source_path is None
    assert engine.fingerprint is None
    assert engine.revision == "unversioned"


def test_unchanged_policy_does_not_reload(gov):
    governor, _ = gov
    assert governor.maybe_reload_policy() is None
    assert governor.maybe_reload_policy() is None


# ------------------------------------------------------------------------ reload


def test_changed_policy_takes_effect_without_restart(gov):
    governor, policy_path = gov
    seed_confidential(governor)

    before = governor.recall("contract Northwind", principal=ALICE)
    assert before["results"] == []
    assert before["denied"][0]["rule"] == "insufficient_clearance"

    # A reviewer raises the employee clearance. No restart, no re-instantiation.
    write_policy(policy_path, revision="2", employee_clearance=2)

    after = governor.recall("contract Northwind", principal=ALICE)
    assert len(after["results"]) == 1
    assert "2,400,000" in after["results"][0]["content"]
    assert governor.policy.revision == "2"


def test_reload_is_audited_with_both_fingerprints_and_a_diff(gov):
    governor, policy_path = gov
    old_fingerprint = governor.policy.fingerprint
    write_policy(policy_path, revision="2", employee_clearance=3)

    result = governor.maybe_reload_policy()
    assert result is not None
    assert result["revision"] == "2"

    changes = [e for e in governor.audit.entries() if e["event"] == "policy.changed"]
    assert len(changes) == 1
    event = changes[0]
    assert event["old_sha256"] == old_fingerprint
    assert event["new_sha256"] == governor.policy.fingerprint
    assert event["revision"] == "2"
    assert any("roles.employee.clearance" in c for c in event["changes"])
    assert "1 -> 3" in " ".join(event["changes"])


def test_reload_fires_on_the_next_write_operation(gov):
    """Operators edit the file; the governor notices on the next call."""
    governor, policy_path = gov
    write_policy(policy_path, revision="9", employee_clearance=2)

    governor.remember("A new fact.", source="wiki", tenant=TENANT, scope="project")

    assert governor.policy.revision == "9"
    assert any(e["event"] == "policy.changed" for e in governor.audit.entries())


def test_reload_rewires_everything_that_reads_policy(gov):
    """A forgotten rebind would judge deletions against the previous revision.

    Deleting a protected scope is the sharpest available probe: it goes through
    `Maintenance`, which holds its own reference to the policy engine.
    """
    governor, policy_path = gov
    seed_confidential(governor)
    memory_id = governor.store.all_items(TENANT)[0].id

    refused = governor.forget(principal=ALICE, ids=[memory_id], reason="test")
    assert refused["deleted"] is False  # confidential is not deletable

    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "revision": "3",
                "scopes": {"confidential": {"min_clearance": 2, "deletable": True}},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    governor.maybe_reload_policy()
    assert governor.maintenance.policy is governor.policy, "maintenance kept the old engine"

    allowed = governor.forget(principal=ALICE, ids=[memory_id], reason="now permitted")
    assert allowed["deleted"] is True
    assert governor.store.get(memory_id) is None


def test_broken_policy_edit_keeps_serving_and_is_reported_once(tmp_path: Path):
    """A typo must not become an outage, and must not flood the audit log."""
    policy_path = tmp_path / "p.yaml"
    write_policy(policy_path, revision="1", employee_clearance=1)
    gov = MemoryGovernor(
        policy_path=policy_path,
        db_path=tmp_path / "m.db",
        audit_path=tmp_path / "a.jsonl",
    )
    try:
        policy_path.write_text(
            "version: 1\nrevision: 'broken'\nscopes:\n  weird:\n    deletable: true\n",
            encoding="utf-8",
        )

        result = gov.maybe_reload_policy()
        assert result is not None
        assert result["reloaded"] is False
        assert "min_clearance" in result["error"]
        assert gov.policy.revision == "1", "last known good policy stays active"

        # The layer keeps working on the previous revision.
        stored = gov.remember("Still serving.", source="wiki", tenant=TENANT, scope="project")
        assert stored["stored"] is True

        failures = [e for e in gov.audit.entries() if e["event"] == "policy.reload_failed"]
        assert len(failures) == 1, "the same broken revision is reported once, not per request"
        assert failures[0]["active_revision"] == "1"
    finally:
        gov.close()


def test_reload_recovers_once_the_broken_file_is_fixed(tmp_path: Path):
    policy_path = tmp_path / "p.yaml"
    write_policy(policy_path, revision="1", employee_clearance=1)
    gov = MemoryGovernor(
        policy_path=policy_path,
        db_path=tmp_path / "m.db",
        audit_path=tmp_path / "a.jsonl",
    )
    try:
        policy_path.write_text("version: 1\nscopes:\n  weird:\n    deletable: true\n", "utf-8")
        assert gov.maybe_reload_policy()["reloaded"] is False

        write_policy(policy_path, revision="2", employee_clearance=2)
        assert gov.maybe_reload_policy()["reloaded"] is True
        assert gov.policy.revision == "2"
    finally:
        gov.close()


# ------------------------------------------------------------------- diffing


def test_every_audit_entry_records_the_policy_revision(gov):
    """A historical decision must be tieable to the permissions that permitted it."""
    governor, _ = gov
    seed_confidential(governor)
    governor.recall("contract Northwind", principal=ALICE)

    entries = list(governor.audit.entries())
    assert entries
    assert all(e.get("policy_revision") == "1" for e in entries), [
        e["event"] for e in entries if e.get("policy_revision") != "1"
    ]


def test_audit_still_records_the_revision_after_a_reload(gov):
    governor, policy_path = gov
    seed_confidential(governor)
    governor.recall("contract", principal=ALICE)  # revision 1
    write_policy(policy_path, revision="2", employee_clearance=2)
    governor.recall("contract", principal=ALICE)  # reloads, then revision 2

    revisions = [e.get("policy_revision") for e in governor.audit.entries()]
    assert "1" in revisions
    assert "2" in revisions


def test_diff_reports_additions_removals_and_changes():
    old = {"roles": {"employee": {"clearance": 1}}, "read": {"min_confidence": 0.3}}
    new = {"roles": {"employee": {"clearance": 2}, "hr": {"clearance": 3}},
           "read": {"min_confidence": 0.5}}
    changes = diff_configs(old, new)
    joined = " ".join(changes)
    assert "roles.employee.clearance: 1 -> 2" in joined
    assert "roles.hr: added" in joined
    assert "read.min_confidence: 0.3 -> 0.5" in joined


def test_diff_is_empty_for_identical_configs():
    config = {"roles": {"employee": {"clearance": 1}}}
    assert diff_configs(config, config) == []


def test_diff_truncates_very_long_values():
    changes = diff_configs({"k": "x" * 500}, {"k": "y" * 500})
    assert len(changes) == 1
    assert len(changes[0]) < 200


# ------------------------------------------------------- locating the policy file


def test_the_two_policy_copies_do_not_drift():
    """Two copies exist on purpose: one ships inside the package, one sits at the repo
    root as the file you edit and point `--policy` at. They must stay identical, or the
    "default" silently means two different things again."""
    repo = Path(__file__).resolve().parents[1]
    editable = repo / "policies" / "default.yaml"
    packaged = repo / "src" / "amnesia" / "policies" / "default.yaml"
    assert editable.is_file(), "the editable copy is missing"
    assert packaged.is_file(), "the packaged copy is missing"
    assert editable.read_bytes() == packaged.read_bytes(), (
        "policies/default.yaml and src/amnesia/policies/default.yaml have diverged; "
        "they must be kept byte-identical"
    )


def test_the_shipped_policy_is_reachable_next_to_the_package():
    path = shipped_policy_path()
    assert path is not None and path.is_file()
    engine = PolicyEngine.from_yaml(path)
    assert engine.revision != UNVERSIONED
    assert engine.fingerprint is not None


def test_a_missing_policy_file_is_reported_as_such(tmp_path: Path):
    """A typo in --policy must not surface as a bare FileNotFoundError from pathlib."""
    with pytest.raises(PolicyError, match="not found"):
        PolicyEngine.from_yaml(tmp_path / "nope.yaml")


def test_a_directory_instead_of_a_policy_file_is_rejected(tmp_path: Path):
    target = tmp_path / "adir"
    target.mkdir()
    with pytest.raises(PolicyError):
        PolicyEngine.from_yaml(target)


def test_resolver_precedence(tmp_path: Path, monkeypatch):
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("version: 1\nrevision: 'explicit'\n", encoding="utf-8")

    # An explicit argument wins over everything.
    monkeypatch.setenv("AMNESIA_POLICY", str(tmp_path / "from-env.yaml"))
    assert resolve_policy_path(explicit) == explicit

    # Then the environment variable.
    assert resolve_policy_path() == tmp_path / "from-env.yaml"

    # Then the shipped default.
    monkeypatch.delenv("AMNESIA_POLICY")
    assert resolve_policy_path() == shipped_policy_path()


def test_resolver_can_yield_nothing_when_no_source_exists(monkeypatch):
    monkeypatch.delenv("AMNESIA_POLICY", raising=False)
    monkeypatch.setattr("amnesia.policy.shipped_policy_path", lambda: None)
    assert resolve_policy_path() is None
