"""The audit hash chain.

"A tamper-evident trail" is the claim the product rests on. Before the chain existed it was only
a docstring, so these tests are the difference between the claim and the fact.
"""

from __future__ import annotations

import json
from pathlib import Path

from amnesia import MemoryGovernor
from amnesia.audit import AuditLog
from amnesia.chain import GENESIS, digest, verify

REPO = Path(__file__).resolve().parents[1]


def _log(tmp_path: Path, count: int = 6) -> tuple[AuditLog, Path]:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    for i in range(count):
        log.record("memory.write", tenant="acme", outcome="stored", i=i)
    return log, path


def _entries(path: Path) -> list[dict]:
    """Parse every readable line. Skips damaged ones, exactly as the product does — the point of
    these tests is often that a damaged line exists."""
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _rewrite(path: Path, entries: list[dict]) -> Path:
    path.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n", encoding="utf-8"
    )
    return path


# ------------------------------------------------------------------ the happy path


def test_a_fresh_log_chains_and_verifies(tmp_path: Path):
    log, path = _log(tmp_path)
    entries = _entries(path)
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5, 6]
    assert entries[0]["prev"] == GENESIS
    assert entries[1]["prev"] == entries[0]["hash"]

    status = log.chain_status()
    assert status.state == "intact"
    assert status.ok and status.chained == 6 and status.unchained == 0
    assert "intact over 6 entries" in status.describe()


def test_an_empty_log_verifies_as_intact(tmp_path: Path):
    log = AuditLog(tmp_path / "a.jsonl")
    status = log.chain_status()
    assert status.state == "intact" and status.chained == 0


def test_the_digest_survives_reformatting(tmp_path: Path):
    """Sorted keys and no whitespace, so an intermediary that pretty-prints the log — or a
    different JSON writer — must not break the chain. The digest covers content, not layout."""
    _, path = _log(tmp_path, 3)
    entries = _entries(path)
    entry = entries[1]
    assert digest(entry["seq"], entry["prev"], entry) == entry["hash"]
    # Same content, different key order and spacing.
    shuffled = dict(reversed(list(entry.items())))
    assert digest(shuffled["seq"], shuffled["prev"], shuffled) == entry["hash"]


# ------------------------------------------------------------------- the three edits


def test_modifying_an_entry_is_detected(tmp_path: Path):
    _, path = _log(tmp_path)
    entries = _entries(path)
    entries[2]["outcome"] = "approved_anyway"
    status = verify(_entries(_rewrite(path, entries)))

    assert status.state == "broken" and not status.ok
    assert status.first_break_index == 2
    assert "do not match their own hash" in status.describe()


def test_deleting_an_entry_is_detected(tmp_path: Path):
    """A modification breaks a hash; a deletion cannot, because the remaining entries are all
    internally consistent. The sequence number is what catches it."""
    _, path = _log(tmp_path)
    entries = _entries(path)
    status = verify(_entries(_rewrite(path, entries[:2] + entries[3:])))

    assert status.state == "broken"
    assert "sequence gap" in status.describe()


def test_reordering_entries_is_detected(tmp_path: Path):
    _, path = _log(tmp_path)
    entries = _entries(path)
    entries[3], entries[4] = entries[4], entries[3]
    status = verify(_entries(_rewrite(path, entries)))

    assert status.state == "broken"
    assert "prev hash does not match" in status.describe()


def test_appending_a_forged_entry_is_detected(tmp_path: Path):
    """The interesting case: an attacker who knows the format and computes a plausible hash
    still cannot sign an entry without the previous one, and a fabricated hash does not verify."""
    _, path = _log(tmp_path)
    entries = _entries(path)
    entries.append(
        {
            "ts": "2026-10-03T00:00:00+00:00",
            "event": "memory.forget",
            "tenant": "acme",
            "outcome": "deleted",
            "seq": len(entries) + 1,
            "prev": entries[-1]["hash"],
            "hash": "0" * 64,
        }
    )
    status = verify(_entries(_rewrite(path, entries)))
    assert status.state == "broken"
    assert "do not match their own hash" in status.describe()


def test_truncating_the_tail_is_a_limitation_not_a_detection(tmp_path: Path):
    """Stated plainly rather than left as a surprise: a chain with no external anchor cannot
    detect truncation, because every remaining entry is still consistent. Anchoring the head
    digest somewhere the log's owner does not control is a deployment decision, and this test
    records that it is one — not something the library silently pretends to do."""
    _, path = _log(tmp_path)
    entries = _entries(path)
    status = verify(_entries(_rewrite(path, entries[:3])))
    assert status.state == "intact", "truncation leaves a self-consistent prefix"
    assert status.chained == 3


# ----------------------------------------------------------- legacy and concurrency


def test_entries_predating_the_chain_report_partial(tmp_path: Path):
    """Not `broken`. A log that cannot be verified is a different situation from one that has
    been tampered with, and conflating them would cry wolf on every upgraded deployment."""
    _, path = _log(tmp_path, 3)
    legacy = [
        {"ts": "2026-01-01T00:00:00+00:00", "event": "memory.write", "tenant": "acme"},
    ]
    status = verify(legacy + _entries(path))

    assert status.state == "partial"
    assert status.ok, "an unverifiable prefix is not a failure"
    assert status.unchained == 1 and status.chained == 3
    assert "predate chaining" in status.describe()


def test_concurrent_appends_still_chain(tmp_path: Path):
    """The reason appending takes an exclusive lock.

    Chaining needs the previous hash, so an append is a read-modify-write. Without the lock two
    writers read the same predecessor and the log becomes indistinguishable from tampering —
    and a tamper-evident log that cries wolf under ordinary load is worse than no chain.
    """
    import threading

    log = AuditLog(tmp_path / "a.jsonl")
    errors: list[str] = []

    def worker(n: int) -> None:
        try:
            for i in range(15):
                log.record("memory.write", tenant="acme", worker=n, i=i)
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, errors
    status = log.chain_status()
    assert status.state == "intact", status.describe()
    assert status.chained == 90


def test_a_broken_tail_starts_a_new_segment_instead_of_refusing(tmp_path: Path):
    """A half-written line is a normal thing to find in a file customers grep and archive.
    Refusing to audit would be the worse outcome; starting a visible new segment is not."""
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.record("memory.write", tenant="acme")

    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"ts": "2026-10-03T00:00:00+00:00", "event": "trunc\n')

    log.record("memory.write", tenant="acme")
    assert _entries(path)[-1]["seq"] == 1, "the new entry starts a fresh segment"

    status = log.chain_status()
    assert status.ok, "a damaged tail is not tampering"
    assert status.unreadable == 1 or status.unchained >= 1


def test_a_damaged_line_does_not_make_the_log_unreadable(tmp_path: Path):
    """The failure this guards is not the damaged line itself, it is the blast radius.

    `json.loads` raising inside `entries()` took down `report`, `verify`, `explain` and `flagged`
    at once — one bad line anywhere made the entire trail unreadable, which is the opposite of
    what an evidence store should do. Here the damaging write has no trailing newline, so the
    next append lands on the same line and corrupts both.
    """
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.record("memory.write", tenant="acme", outcome="stored")
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"ts": "2026-10-03T00:00:00+00:00", "event": "trunc')  # no newline
    log.record("memory.forget", tenant="acme", outcome="deleted")

    parsed = list(log.entries())          # must not raise
    assert log.unreadable_lines >= 1
    assert all(isinstance(e, dict) for e in parsed)
    assert log.tail(5)                    # `audit --tail` still works


def test_a_damaged_line_anywhere_leaves_the_rest_readable(tmp_path: Path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.record("memory.write", tenant="acme", i=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines.insert(2, "{ this is not json")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    good = list(log.entries())
    assert [e.get("i") for e in good] == [0, 1, 2, 3]
    assert log.unreadable_lines == 1

    # `partial`, not `broken`: skipping the damaged line leaves the surviving sequence intact,
    # so nothing is *inconsistent* — but the log is incomplete and says so. The distinction
    # matters, because `broken` accuses someone and `partial` does not.
    status = log.chain_status()
    assert status.state == "partial"
    assert status.ok
    assert "could not be parsed" in status.describe()


def test_the_diagnostic_separates_partial_from_broken(tmp_path: Path):
    """`verify` must not report an unverifiable log as a clean bill of health."""
    from amnesia.diagnostics import run_checks

    path = tmp_path / "a.jsonl"
    governor = MemoryGovernor(
        policy_path=REPO / "policies" / "default.yaml",
        db_path=tmp_path / "m.db",
        audit_path=path,
    )
    try:
        governor.remember("A note.", source="wiki", tenant="acme", scope="project")
        healthy = {c.name: c for c in run_checks(governor)}
        assert healthy["audit chain"].status == "ok"

        # Now damage it: an unparseable line leaves the chain partial.
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("{ not json\n" + "\n".join(lines) + "\n", encoding="utf-8")
        degraded = {c.name: c for c in run_checks(governor)}
        assert degraded["audit chain"].status == "warn"

        # And tampering is a failure, not a warning.
        entries = _entries(path)
        entries[0]["event"] = "memory.nothing_happened"
        _rewrite(path, entries)
        tampered = {c.name: c for c in run_checks(governor)}
        assert tampered["audit chain"].status == "fail"
    finally:
        governor.close()
