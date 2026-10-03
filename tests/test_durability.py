"""Validation, durability and migration.

Two categories of test live here, both about behaving like a program rather than a
script:

  - bad input is rejected before it can produce a misleading audit record
  - the database survives real conditions: an old schema, concurrent writers, and a
    restart
"""

from __future__ import annotations

import errno
import sqlite3
import threading
from pathlib import Path

import pytest

from amnesia import (
    BackendError,
    MemoryGovernor,
    MemoryStore,
    PolicyError,
    Principal,
    ValidationError,
    utcnow,
)
from amnesia.validation import MAX_TAGS, validate_principal, validate_recall, validate_write

TENANT = "acme"
ALICE = Principal(id="alice", tenant=TENANT, roles=("employee",))


@pytest.fixture()
def gov(tmp_path: Path):
    g = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    yield g
    g.close()


# ------------------------------------------------------------------- validation


def test_content_must_be_a_string(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.remember(b"bytes", source="s", tenant=TENANT)  # type: ignore[arg-type]


def test_content_must_not_be_empty(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.remember("   ", source="s", tenant=TENANT)


def test_oversized_content_is_rejected_not_truncated(gov: MemoryGovernor):
    """Truncating would make the audit record describe a document that never existed."""
    with pytest.raises(ValidationError) as excinfo:
        gov.remember("x" * (300 * 1024), source="s", tenant=TENANT)
    assert "above" in str(excinfo.value)


def test_tenant_is_required(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.remember("hello", source="s", tenant="")


def test_an_omitted_scope_falls_back_to_the_default(gov: MemoryGovernor):
    """A missing scope means "use the default", which is normalisation, not an error."""
    result = gov.remember("hello", source="s", tenant=TENANT)
    assert result["stored"] is True
    assert result["scope"] == "project"

    explicit_none = gov.remember("hello again", source="s", tenant=TENANT, scope=None)
    assert explicit_none["stored"] is True
    assert explicit_none["scope"] == "project"


def test_an_empty_scope_is_an_error_not_the_default(gov: MemoryGovernor):
    """`scope=""` is not "omitted", and treating it as the default was fail-open.

    An empty string means a caller tried to supply a scope and failed — an unset shell variable,
    an empty form field, an MCP argument dropped in transit. Silently promoting that to `project`
    places a memory the caller meant to restrict where everyone can read it.

    This test is the correction of a real defect: the previous test asserted the fail-open
    behaviour, which is why nothing caught it.
    """
    with pytest.raises(ValidationError, match="supplied but empty"):
        gov.remember("hello", source="s", tenant=TENANT, scope="")

    with pytest.raises(ValidationError, match="supplied but empty"):
        gov.remember("hello", source="s", tenant=TENANT, scope="   ")

    # And nothing was written on the way to the error.
    assert gov.store.count(TENANT) == 0


def test_confidence_must_be_within_range(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.remember("hello", source="s", tenant=TENANT, confidence=1.5)
    with pytest.raises(ValidationError):
        gov.remember("hello", source="s", tenant=TENANT, confidence=-0.1)


def test_confidence_must_be_numeric(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.remember("hello", source="s", tenant=TENANT, confidence=True)  # type: ignore[arg-type]


def test_too_many_tags_are_rejected(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.remember(
            "hello", source="s", tenant=TENANT, tags=[f"t{i}" for i in range(MAX_TAGS + 1)]
        )


def test_validation_precedes_every_side_effect(gov: MemoryGovernor):
    """A rejected call must leave no memory, no attempt and no audit record."""
    with pytest.raises(ValidationError):
        gov.remember("x" * (300 * 1024), source="s", tenant=TENANT, subject="s1")
    assert gov.store.count() == 0
    assert gov.store.count_attempts_since(
        tenant=TENANT, subject="s1", since=utcnow().replace(year=2000)
    ) == 0
    assert list(gov.audit.entries()) == []


def test_unknown_scope_is_a_policy_error(gov: MemoryGovernor):
    with pytest.raises(PolicyError):
        gov.remember("hello", source="s", tenant=TENANT, scope="nonsense")


def test_principal_requires_roles():
    with pytest.raises(ValidationError):
        validate_principal(Principal(id="x", tenant=TENANT, roles=()))


def test_principal_requires_id_and_tenant():
    with pytest.raises(ValidationError):
        validate_principal(Principal(id="", tenant=TENANT, roles=("employee",)))
    with pytest.raises(ValidationError):
        validate_principal(Principal(id="x", tenant="", roles=("employee",)))


def test_recall_rejects_bad_limits_and_modes(gov: MemoryGovernor):
    with pytest.raises(ValidationError):
        gov.recall("q", principal=ALICE, limit=0)
    with pytest.raises(ValidationError):
        gov.recall("q", principal=ALICE, limit=10_000)
    with pytest.raises(ValidationError):
        gov.recall("q", principal=ALICE, mode="sideways")


def test_validation_helpers_are_importable_and_direct():
    validate_write(
        content="ok", source="s", tenant=TENANT, scope="project", tags=["a"]
    )
    validate_recall(query="q", limit=5, mode="post_filter")
    validate_principal(ALICE)


# -------------------------------------------------------------------- durability


def test_file_backend_defaults_to_the_rollback_journal(tmp_path: Path):
    """WAL is opt-in.

    It is a concurrency improvement, not a correctness one -- and on a filesystem that cannot
    sustain its shared-memory file, entering WAL is a correctness regression. Measured with
    plain sqlite3 and 30 concurrent writers: WAL 21/30 and 25/30, the rollback journal 30/30.
    """
    store = MemoryStore(tmp_path / "m.db")
    try:
        health = store.health()
        assert health["journal_mode"] == "delete"
        assert health["requested_journal_mode"] == "auto"
        assert health["synchronous"] == 2  # FULL
    finally:
        store.close()


def test_wal_can_be_requested_explicitly(tmp_path: Path):
    store = MemoryStore(tmp_path / "m.db", journal_mode="wal")
    try:
        assert store.health()["journal_mode"] == "wal"
    finally:
        store.close()


def test_auto_keeps_a_file_that_is_already_wal(tmp_path: Path):
    """An operator who enabled WAL on a capable filesystem should not be walked back by the
    next process, which only knows the file's current mode."""
    db = tmp_path / "m.db"
    MemoryStore(db, journal_mode="wal").close()

    second = MemoryStore(db, journal_mode="auto")
    try:
        assert second.health()["journal_mode"] == "wal"
    finally:
        second.close()


def test_durability_can_be_relaxed_explicitly(tmp_path: Path):
    store = MemoryStore(tmp_path / "m.db", durability="normal")
    try:
        assert store.health()["synchronous"] == 1
    finally:
        store.close()


def test_invalid_durability_is_rejected(tmp_path: Path):
    with pytest.raises(BackendError):
        MemoryStore(tmp_path / "m.db", durability="eventually")


# ------------------------------------------------ journal mode and its fallback


def test_journal_mode_can_be_forced_to_the_rollback_journal(tmp_path: Path):
    store = MemoryStore(tmp_path / "m.db", journal_mode="delete")
    try:
        assert store.health()["journal_mode"] == "delete"
        assert store.degradations == []
    finally:
        store.close()


def test_forcing_wal_disables_the_fallback(tmp_path: Path):
    """An operator who asks for WAL should get a failure, not a silent contradiction."""
    store = MemoryStore(tmp_path / "m.db", journal_mode="wal")
    try:
        assert store.health()["journal_mode"] == "wal"
        assert store._downgrade_from_wal() is False
        assert store.degradations == []
    finally:
        store.close()


def test_invalid_journal_mode_is_rejected(tmp_path: Path):
    with pytest.raises(BackendError):
        MemoryStore(tmp_path / "m.db", journal_mode="magic")


def test_a_journal_fallback_outlives_the_process(tmp_path: Path):
    """The fallback must be recorded in the database, not in memory.

    Every CLI invocation is a fresh process. An in-memory flag is forgotten immediately, the
    next process re-enables WAL, hits the same failure, and the store never converges -- which
    is exactly what happened when ten concurrent writers were pointed at one fresh file and
    the failure count oscillated instead of settling.
    """
    db = tmp_path / "m.db"

    # An operator enabled WAL on a filesystem that turned out not to sustain it.
    MemoryStore(db, journal_mode="wal").close()
    first = MemoryStore(db, journal_mode="auto")
    try:
        assert first.health()["journal_mode"] == "wal"
        assert first._downgrade_from_wal() is True
        assert first.health()["journal_mode"] == "delete"
        assert first.degradations, "a degradation nobody can see is not a degradation"
    finally:
        first.close()

    # A brand-new store on the same file, as a later CLI invocation would create.
    second = MemoryStore(db)
    try:
        assert second.health()["journal_mode"] == "delete", "the decision was not remembered"
        assert second.requested_journal_mode == "auto"
    finally:
        second.close()


def test_the_fallback_is_idempotent_within_one_store(tmp_path: Path):
    """It may be offered to a caller more than once, but must degrade only once.

    A second `True` is meaningful: it tells the caller "the mode is now delete, retry the
    write". A second degradation *record* would not be -- it would multiply the warning.
    """
    db = tmp_path / "m.db"
    MemoryStore(db, journal_mode="wal").close()
    store = MemoryStore(db, journal_mode="auto")  # inherits the WAL the operator set
    try:
        assert store.health()["journal_mode"] == "wal"
        assert store._downgrade_from_wal() is True
        assert len(store.degradations) == 1
        assert store._downgrade_from_wal() is False, "already stepped down; nothing changed"
        assert len(store.degradations) == 1
    finally:
        store.close()


def test_a_store_already_on_the_rollback_journal_offers_a_retry(tmp_path: Path):
    """If it is already in delete mode and a write still failed, retrying is the right advice.

    Returning False here would re-raise an error for a write that would now succeed.
    """
    store = MemoryStore(tmp_path / "m.db", journal_mode="delete")
    try:
        assert store._downgrade_from_wal() is True
        assert store.degradations == [], "nothing was degraded; it started in delete mode"
        assert store._downgrade_from_wal() is False
    finally:
        store.close()


def test_health_reports_the_requested_and_effective_modes(tmp_path: Path):
    store = MemoryStore(tmp_path / "m.db", journal_mode="auto")
    try:
        health = store.health()
        assert health["requested_journal_mode"] == "auto"
        assert health["journal_mode"] in ("wal", "delete")
        assert health["degradations"] == []
    finally:
        store.close()


def test_the_fallback_also_applies_after_reopening(tmp_path: Path):
    """The reconnect that follows a fallback must not undo it."""
    store = MemoryStore(tmp_path / "m.db")
    try:
        assert store._downgrade_from_wal() is True
        store._reopen()
        assert store.health()["journal_mode"] == "delete"
    finally:
        store.close()


def test_memory_backend_skips_wal(tmp_path: Path):
    store = MemoryStore(":memory:")
    try:
        assert store.health()["integrity"] == "ok"
    finally:
        store.close()


def test_an_audit_path_that_is_a_directory_is_reported_clearly(tmp_path: Path):
    """A configuration mistake must not surface as a bare PermissionError from pathlib.

    It used to raise on the first *append*, several layers below anything that could explain
    it, and `PermissionError` is not an `AmnesiaError`, so the CLI did not catch it and the
    operator got a traceback for a mistyped path.
    """
    from amnesia.audit import AuditLog

    target = tmp_path / "auditdir"
    target.mkdir()
    with pytest.raises(BackendError, match="not a file"):
        AuditLog(target)


def test_corrupt_path_raises_backend_error(tmp_path: Path):
    """A directory where the database should be is a configuration error, not a crash."""
    target = tmp_path / "not-a-db"
    target.mkdir()
    with pytest.raises(BackendError):
        MemoryStore(target)


# --------------------------------------------------------------------- migration


LEGACY_SCHEMA = """
CREATE TABLE memories (
    id            TEXT PRIMARY KEY,
    content       TEXT NOT NULL,
    source        TEXT NOT NULL,
    tenant        TEXT NOT NULL,
    scope         TEXT NOT NULL,
    owner         TEXT NOT NULL,
    subject       TEXT NOT NULL DEFAULT '',
    confidence    REAL NOT NULL DEFAULT 1.0,
    tags          TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    last_access   TEXT,
    expires_at    TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    superseded_by TEXT
);
"""


def _legacy_db(path: Path, content: str) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.execute(
        "INSERT INTO memories (id, content, source, tenant, scope, owner, created_at)"
        " VALUES ('legacy1', ?, 'wiki', ?, 'project', 'o', ?)",
        (content, TENANT, utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def test_legacy_database_is_upgraded_in_place(tmp_path: Path):
    path = tmp_path / "legacy.db"
    _legacy_db(path, "Falcon programme quarterly report")

    store = MemoryStore(path)
    try:
        health = store.health()
        assert health["schema_version"] == 2
        assert health["index_fresh"] is True, "the term index must be rebuilt"

        # The pre-existing memory is retrievable, which is the point of migrating.
        pairs = store.search_candidates(
            "Falcon programme", tenant=TENANT, min_confidence=0.0, now=utcnow(), limit=5
        )
        assert [item.id for item, _ in pairs] == ["legacy1"]
    finally:
        store.close()


def test_migration_is_idempotent(tmp_path: Path):
    path = tmp_path / "legacy.db"
    _legacy_db(path, "Falcon programme")

    for _ in range(3):
        store = MemoryStore(path)
        try:
            assert store.health()["schema_version"] == 2
            assert store.count() == 1
        finally:
            store.close()


def test_reindex_is_available_after_a_tokenizer_change(tmp_path: Path):
    path = tmp_path / "m.db"
    store = MemoryStore(path)
    try:
        gov = MemoryGovernor(store=MemoryStore(path), audit_path=tmp_path / "a.jsonl")
        gov.remember("Falcon programme", source="wiki", tenant=TENANT, scope="project")
        gov.close()
        assert store.reindex() == 1
    finally:
        store.close()


# ------------------------------------------------------------------ concurrency


def test_concurrent_writers_do_not_lose_records(tmp_path: Path):
    """An MCP server serves concurrent requests, so this is a real path, not theory."""
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    failures: list[BaseException] = []
    per_thread, threads_n = 6, 4

    def worker(worker_id: int) -> None:
        try:
            for i in range(per_thread):
                gov.remember(
                    f"thread {worker_id} note {i}",
                    source="wiki",
                    tenant=TENANT,
                    scope="project",
                )
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(threads_n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    try:
        assert not failures, f"concurrent writes raised: {failures!r}"
        assert gov.store.count(TENANT) == per_thread * threads_n
        assert len(gov.store.attempts(TENANT)) == per_thread * threads_n
        assert gov.store.health()["integrity"] == "ok"
    finally:
        gov.close()


def test_concurrent_reads_and_writes_interleave(tmp_path: Path):
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    failures: list[BaseException] = []
    stop = threading.Event()

    def reader() -> None:
        try:
            while not stop.is_set():
                gov.recall("note", principal=ALICE)
        except BaseException as exc:
            failures.append(exc)

    def writer() -> None:
        try:
            for i in range(20):
                gov.remember(f"note {i}", source="wiki", tenant=TENANT, scope="project")
        except BaseException as exc:
            failures.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(2)]
    writers = [threading.Thread(target=writer) for _ in range(2)]
    for thread in [*readers, *writers]:
        thread.start()
    for thread in writers:
        thread.join(timeout=30)
    stop.set()
    for thread in readers:
        thread.join(timeout=30)

    try:
        assert not failures, f"interleaved access raised: {failures!r}"
        assert gov.store.count(TENANT) == 40
    finally:
        gov.close()


def test_tail_is_correct_across_multiple_read_blocks(tmp_path: Path):
    """`tail` reads backwards from the end; the log here is larger than one read block."""
    from amnesia import AuditLog

    log = AuditLog(tmp_path / "big.jsonl")
    for i in range(400):
        log.record("test.event", index=i, payload="x" * 200)
    assert (tmp_path / "big.jsonl").stat().st_size > 64 * 1024

    tail = log.tail(10)
    assert [entry["index"] for entry in tail] == list(range(390, 400))
    # And it must agree with the naive reading of the whole stream.
    assert tail == list(log.entries())[-10:]


def test_tail_on_a_missing_log_is_empty(tmp_path: Path):
    from amnesia import AuditLog

    assert AuditLog(tmp_path / "absent.jsonl").tail(5) == []


def test_a_transient_file_access_error_is_retried(tmp_path: Path):
    """On Windows a file another handle has open reads as "permission denied", and that is
    frequently transient -- antivirus, the search indexer, a process deleting the journal file.

    It reaches us as a bare `PermissionError`, not as a `sqlite3.Error`, so retry logic that
    only covered sqlite3 let a governed write fail outright. That is how the interleaved
    read/write test failed for real: the host refused one journal-file deletion.
    """
    store = MemoryStore(tmp_path / "m.db")
    real = store._conn
    try:
        store._conn = _FlakyConnection(real, errno_=errno.EACCES)
        store._write(lambda: store._conn.execute("CREATE TABLE IF NOT EXISTS t (x)"))
        assert store._conn.calls == 2, "the transient error was not retried"
    finally:
        store._conn = real
        store.close()


def test_a_permanent_error_is_not_retried(tmp_path: Path):
    """Disk full will not clear if you wait, so retrying only delays the error."""
    store = MemoryStore(tmp_path / "m.db")
    real = store._conn
    try:
        store._conn = _FlakyConnection(real, errno_=errno.ENOSPC, fail_times=99)
        with pytest.raises(OSError):
            store._write(lambda: store._conn.execute("CREATE TABLE IF NOT EXISTS t (x)"))
        assert store._conn.calls == 1
    finally:
        store._conn = real
        store.close()


def test_contention_classification(tmp_path: Path):
    from amnesia.errors import is_transient

    assert is_transient(sqlite3.OperationalError("database is locked")) is True
    assert is_transient(sqlite3.OperationalError("attempt to write a readonly database")) is True
    assert is_transient(PermissionError(errno.EACCES, "denied")) is True
    # Not contention: retrying these would only delay the error.
    assert is_transient(sqlite3.OperationalError("no such table: memories")) is False
    assert is_transient(OSError(errno.ENOSPC, "No space left on device")) is False
    # EPERM is treated as permanent. On Windows errno.EPERM is 1, so this also pins that the
    # retry set is deliberate rather than "any OSError".
    assert is_transient(PermissionError(errno.EPERM, "denied")) is False


class _FlakyConnection:
    """A connection wrapper that fails the first `fail_times` calls with an OSError.

    Needed because `sqlite3.Connection` is a C object and will not accept attribute
    assignment, so a proxy is the only way to inject a failure from outside.
    """

    def __init__(self, real, *, fail_times: int = 1, errno_: int = errno.EACCES):
        self._real = real
        self._left = fail_times
        self.calls = 0
        self.errno = errno_

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute(self, *args, **kwargs):
        self.calls += 1
        if self._left:
            self._left -= 1
            raise OSError(self.errno, "Permission denied")
        return self._real.execute(*args, **kwargs)

    def __enter__(self):
        return self._real.__enter__()

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)


def test_data_survives_reopening(tmp_path: Path):
    db = tmp_path / "m.db"
    audit = tmp_path / "a.jsonl"

    first = MemoryGovernor(db_path=db, audit_path=audit)
    first.remember(
        "Falcon programme quarterly report.", source="wiki", tenant=TENANT, scope="project"
    )
    first.close()

    second = MemoryGovernor(db_path=db, audit_path=audit)
    try:
        view = second.recall("Falcon programme", principal=ALICE)
        assert len(view["results"]) == 1
        assert len(list(second.audit.entries())) > 0
    finally:
        second.close()
