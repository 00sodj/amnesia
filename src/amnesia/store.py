"""The memory store: SQLite with a real BM25 index, ACL pushdown, and durability
settings chosen for an audit-bearing workload.

Three decisions worth understanding before changing anything here.

**1. Retrieval is BM25, not a similarity score.**
The earlier implementation ranked by naive token overlap. That is enough to prove
governance logic and useless in production: it has no notion of term rarity, so a
match on "policy" counts as much as a match on a rare identifier. Retrieval is now a
full BM25 implementation (k1=1.2, b=0.75) over an inverted index kept in SQLite, so
there is still no external service to run and no second index to keep in sync.

**2. The two retrieval paths are intentional, and they must agree.**
`search_candidates` applies no authorisation; it exists so the governor can report
*what was withheld*. `search_allowed` pushes the scope predicate into SQL, the only
viable path at scale. Both compute term statistics over the whole tenant corpus
rather than the filtered subset -- otherwise the two paths would rank differently and
quietly disagree about which memory is most relevant.

**3. Durability defaults to FULL, not NORMAL.**
This file holds the evidence for "we deleted that person's data" and "nobody read the
HR records". WAL plus `synchronous=NORMAL` is the usual production choice and can lose
the last committed transaction on power loss. For a governance ledger that is the
wrong trade, so the default is FULL. Pass `durability="normal"` if you have measured
the cost and accept it.
"""

from __future__ import annotations

import contextlib
import json
import math
import re
import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import BackendError, is_transient
from .models import MemoryItem, iso

SCHEMA_VERSION = 2

BM25_K1 = 1.2
BM25_B = 0.75



def _is_readonly(exc: BaseException) -> bool:
    """READONLY is *not* the same kind of problem as BUSY, and treating it as one cost real
    writes.

    BUSY means somebody else holds the lock and will release it; waiting works. READONLY in
    WAL mode means this connection cannot write at all while the journal mode is being changed
    underneath it. Waiting the full retry budget before stepping down meant every process sat
    on the broken mode for seconds while the others did the same: measured at 5/5 clean on an
    idle machine and 6 of 8 trials failing on a loaded one. Reacting on the first occurrence
    collapses that window.
    """
    return "readonly" in str(exc).lower()

_TERM_RE = re.compile(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]+")

# Function words carry no retrieval signal and produce exactly the wrong kind of
# match: without this list, "what is Dana's rating" matches an unrelated contract
# memory because both contain "is". Governed recall is precision work, so noise here
# is not a cosmetic issue.
_STOPWORDS = frozenset(
    ["a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "for", "with", "by", "from", "as", "is", "are", "was", "were", "be", "been", "being", "do", "does", "did", "has", "have", "had", "this", "that", "these", "those", "it", "its", "what", "which", "who", "whom", "whose", "how", "when", "where", "why", "s", "t", "re", "ve", "ll", "d", "m"]
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
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
    superseded_by TEXT,
    doc_len       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories (tenant, status, scope);
CREATE INDEX IF NOT EXISTS idx_memories_subject ON memories (tenant, subject, status);
CREATE INDEX IF NOT EXISTS idx_memories_status ON memories (tenant, status);

-- Inverted index for BM25. Kept in the same file so the whole governed corpus is one
-- artefact to back up, one to encrypt, and one to shred.
CREATE TABLE IF NOT EXISTS terms (
    term      TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    tf        INTEGER NOT NULL,
    PRIMARY KEY (term, memory_id)
);
CREATE INDEX IF NOT EXISTS idx_terms_term ON terms (term);

-- Every write *attempt*, including the ones the gate rejected. The memory table only
-- holds successes, so it cannot show a burst of refused writes -- exactly the
-- signature of someone probing the gate.
CREATE TABLE IF NOT EXISTS write_attempts (
    tenant  TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    source  TEXT NOT NULL,
    scope   TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ts      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_subject ON write_attempts (tenant, subject, ts);

-- Decisions this store has had to make about itself, so they survive the process. A journal
-- mode fallback that lived only in memory would be forgotten by the next CLI invocation,
-- which would re-enable WAL, hit the same failure, and never converge.
CREATE TABLE IF NOT EXISTS store_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _terms_of(chunk: str) -> list[str]:
    """Latin words pass through (minus stopwords); CJK becomes bigrams."""
    if chunk[0].isascii():
        return [] if chunk in _STOPWORDS else [chunk]
    if len(chunk) == 1:
        return [chunk]
    return [chunk[i : i + 2] for i in range(len(chunk) - 1)]


def counts(text: str) -> Counter[str]:
    """Term frequencies used both to build the index and to score a query.

    CJK is split into bigrams rather than single characters: at character level, two
    unrelated Chinese terms collide on any shared character and the result is pure
    noise. Bigrams reach a usable precision level with zero dependencies.

    If you replace this with an embedding-backed retriever, keep the
    `search_candidates` / `search_allowed` contract -- the governance guarantees are
    built on those two methods, not on the ranking function behind them.
    """
    out: Counter[str] = Counter()
    for chunk in _TERM_RE.findall((text or "").lower()):
        out.update(_terms_of(chunk))
    return out


def tokens(text: str) -> set[str]:
    return set(counts(text))


class MemoryStore:
    """Reference `MemoryBackend`. One connection, guarded by a re-entrant lock.

    SQLite connections are not thread-safe and an MCP server happily serves
    concurrent requests, so every access is serialised. At genuinely high write
    volume the answer is a server-backed store behind the same protocol, not a
    cleverer connection pool.
    """

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        durability: str = "full",
        journal_mode: str = "auto",
        busy_timeout_ms: int = 5000,
        open_retries: int = 10,
    ):
        self.path = str(path)
        self._lock = threading.RLock()
        self.requested_journal_mode = journal_mode
        self.durability = durability
        self.busy_timeout_ms = busy_timeout_ms
        # Human-readable notes about guarantees that had to be relaxed at runtime. Surfaced
        # by `health()`, by `amnesia verify`, and in the compliance report -- a degradation
        # nobody can see is indistinguishable from a feature that never worked.
        self.degradations: list[str] = []
        self._journal_fallback_done = False
        # Set once this process has decided WAL cannot be sustained. A reconnect must honour
        # that decision rather than re-deriving it: re-deriving mid-contention can hand back
        # WAL, and the retry then fails for the same reason it was downgraded for.
        self._forced_journal_mode: str | None = None
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        # Separate processes racing to create one file can still collide on the very first
        # transition into WAL, before any of them has set a timeout that would apply. Retrying
        # is the correct answer for a transient lock; failing a governed write is not.
        delay = 0.02
        for attempt in range(max(1, open_retries)):
            try:
                self._conn = sqlite3.connect(self.path, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._configure(
                    durability=durability,
                    journal_mode=journal_mode,
                    busy_timeout_ms=busy_timeout_ms,
                )
                self._conn.executescript(_SCHEMA)
                self._conn.commit()
                self._migrate()
                return
            except sqlite3.Error as exc:
                self._close_quietly()
                if attempt == open_retries - 1 or not is_transient(exc):
                    raise BackendError(
                        f"Cannot open memory store at {self.path!r}: {exc}"
                    ) from exc
                time.sleep(delay)
                delay = min(delay * 2, 0.5)

        raise BackendError(f"Cannot open memory store at {self.path!r}")  # pragma: no cover

    def _close_quietly(self) -> None:
        conn = getattr(self, "_conn", None)
        if conn is not None:
            # The connection may already be unusable; closing it is best-effort cleanup
            # before a retry, and its failure must not mask the original error.
            with contextlib.suppress(sqlite3.Error):
                conn.close()

    # ---- setup ----

    def _configure(self, *, durability: str, journal_mode: str, busy_timeout_ms: int) -> None:
        if durability not in ("full", "normal"):
            raise BackendError(f"durability must be 'full' or 'normal', got {durability!r}")
        if journal_mode not in ("auto", "wal", "delete"):
            raise BackendError(
                f"journal_mode must be 'auto', 'wal' or 'delete', got {journal_mode!r}"
            )

        # Timeout first. Everything below can contend, and a timeout that is set after the
        # contentious operation is not a timeout.
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")

        if self.path != ":memory:":
            current = str(self._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            fallback_recorded = self._journal_fallback_recorded()
            if journal_mode == "wal":
                target = "WAL"
            elif journal_mode == "delete":
                target = "DELETE"
            else:
                # `auto` keeps whatever the file already uses and never switches *into* WAL.
                #
                # WAL is opt-in because it is not a correctness improvement, it is a
                # concurrency one -- and on a filesystem that cannot sustain its shared-memory
                # file it is a correctness *regression*: writes fail with SQLITE_READONLY.
                # Measured with 30 concurrent writer processes on plain sqlite3, no Amnesia
                # code: WAL succeeded 21/30 in a project directory and 25/30 in the system temp
                # directory, while the rollback journal succeeded 30/30 in both.
                #
                # The fallback could in principle discover this and step down, but the
                # discovery itself is a contended operation (the journal-mode switch wants an
                # exclusive lock) and the worst moment for it is the first burst against a
                # fresh store, when no process has recorded the decision yet. Ten concurrent
                # CLI processes still failed 6 of 8 trials that way under load. Not entering
                # WAL in the first place removes the failure mode instead of managing it.
                #
                # Set journal_mode="wal" (or AMNESIA_JOURNAL_MODE=wal) when the store is on a
                # filesystem that supports shared memory.
                target = "WAL" if (current == "wal" and not fallback_recorded) else "DELETE"
            if current != target.lower():
                self._conn.execute(f"PRAGMA journal_mode={target}")

        self._conn.execute(f"PRAGMA synchronous={'FULL' if durability == 'full' else 'NORMAL'}")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def _journal_fallback_recorded(self) -> bool:
        """Has this store already given up on WAL?

        Read from the database, not from memory. Every CLI invocation is a fresh process, so
        a per-process flag would be forgotten immediately: the next process would re-enable
        WAL, hit the same failure, and the store would never converge. Verified by running
        ten concurrent writers and watching the failure count oscillate instead of settling.

        Tolerates a missing table: on a brand-new database this runs before the schema exists,
        and "no record" correctly means "try WAL".
        """
        try:
            row = self._conn.execute(
                "SELECT value FROM store_meta WHERE key = 'journal_fallback'"
            ).fetchone()
        except sqlite3.Error:
            return False
        return bool(row and row["value"] == "delete")

    def _downgrade_from_wal(self) -> bool:
        """Step down from WAL to the rollback journal, once, and remember it.

        Only reachable when the file was already in WAL -- either an operator asked for it, or
        an earlier configuration left it that way. `auto` never enters WAL by itself, so this
        is the recovery path rather than the normal one.

        WAL needs a `-shm` file that every process memory-maps. Some filesystems -- network
        mounts, and the virtualised paths some sandboxes provide -- will not sustain that, and
        the failure does not appear at open time: the connection reports
        "attempt to write a readonly database" on an ordinary write, minutes later.
        """
        if self._journal_fallback_done or self.path == ":memory:":
            return False
        if self.requested_journal_mode == "wal":
            # The operator asked for WAL explicitly. Honour that and report the failure
            # rather than silently contradicting them.
            return False

        # Switching the journal mode needs an exclusive lock, and acquiring one is exactly
        # what is hard right now. Giving up on the first BUSY here was the difference between
        # converging and not: the fallback never happened, so the write was lost instead.
        delay = 0.05
        for attempt in range(12):
            try:
                with self._lock:
                    current = str(
                        self._conn.execute("PRAGMA journal_mode").fetchone()[0]
                    ).lower()
                    if current != "wal":
                        # Somebody else already stepped down, or we were never in WAL. Either
                        # way the goal is met and the caller should retry the write.
                        self._forced_journal_mode = "delete"
                        self._journal_fallback_done = True
                        return True
                    self._conn.execute("PRAGMA journal_mode=DELETE")
                    self._conn.execute(
                        "CREATE TABLE IF NOT EXISTS store_meta ("
                        " key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                    )
                    self._conn.execute(
                        "INSERT OR REPLACE INTO store_meta (key, value)"
                        " VALUES ('journal_fallback', 'delete')"
                    )
                    self._conn.commit()
            except sqlite3.Error:
                if attempt == 11:
                    return False
                time.sleep(delay)
                delay = min(delay * 2, 0.5)
                continue

            self._forced_journal_mode = "delete"
            self._journal_fallback_done = True
            self.degradations.append(
                "journal mode fell back from WAL to DELETE: this filesystem would not sustain "
                "WAL under concurrent writers (SQLITE_READONLY). Writes are safe, but readers "
                "now block during a write instead of running alongside it. Pass "
                'journal_mode="wal" to fail loudly instead, or put the store on a local '
                "filesystem that supports shared memory."
            )
            return True
        return False

    def _migrate(self) -> None:
        """Bring an existing database up to `SCHEMA_VERSION`.

        `CREATE TABLE IF NOT EXISTS` covers new tables but never new columns on old
        tables, so columns are checked explicitly. The term index is rebuilt when it
        is empty while memories exist, which also covers "the tokenizer changed".
        """
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(memories)")}
            if "doc_len" not in columns:
                self._conn.execute(
                    "ALTER TABLE memories ADD COLUMN doc_len INTEGER NOT NULL DEFAULT 0"
                )
            if version < SCHEMA_VERSION:
                indexed = int(self._conn.execute("SELECT COUNT(*) FROM terms").fetchone()[0])
                stored = int(self._conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0])
                if indexed == 0 and stored > 0:
                    self.reindex()
                self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._conn.commit()

    # ---- index maintenance ----

    def _index(self, memory_id: str, content: str) -> int:
        term_counts = counts(content)
        if term_counts:
            self._conn.executemany(
                "INSERT OR REPLACE INTO terms (term, memory_id, tf) VALUES (?, ?, ?)",
                [(term, memory_id, tf) for term, tf in term_counts.items()],
            )
        return sum(term_counts.values())

    def _deindex(self, memory_id: str) -> None:
        self._conn.execute("DELETE FROM terms WHERE memory_id = ?", (memory_id,))

    # ---- write transactions ----

    def _read(self, operation: Callable[[], Any], *, attempts: int = 12) -> Any:
        """Run a read, retrying while another process holds the file.

        Reads collide with the same journal-mode transition that writes do, and the failure is
        just as opaque. Retrying is cheap and removes a class of spurious failures from the
        middle of a governed operation -- a `remember` that stored its memory but failed while
        reading for the duplicate check would report failure for a write that landed, which
        for this CLI's exit-code contract reads as "refused".
        """
        delay = 0.02
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                with self._lock:
                    return operation()
            except (sqlite3.OperationalError, OSError) as exc:
                last = exc
                if not is_transient(exc) or attempt == attempts - 1:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
        if last is None:  # pragma: no cover - the loop either returns or raises
            raise AssertionError("retry loop exited without returning or raising")
        raise last

    def _write(
        self,
        operation: Callable[[], Any],
        *,
        attempts: int = 12,
        allow_fallback: bool = True,
    ) -> Any:
        """Run a write transaction, retrying while another process holds the file.

        A function rather than a context manager on purpose: a generator-based `with` cannot
        be re-entered, so retrying around a `yield` would silently run the body once.

        `busy_timeout` is not sufficient here, and that is not obvious. It does not apply to a
        journal-mode transition, nor to the window in which another process is creating the
        -wal/-shm files, and those surface as SQLITE_READONLY rather than SQLITE_BUSY. With
        ten concurrent CLI processes against one store this lost 23 of 50 writes. Losing a
        governed write to a lock race is not acceptable, so contention is retried and
        anything else is raised immediately.
        """
        delay = 0.02
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                with self._lock, self._conn:
                    return operation()
            except (sqlite3.OperationalError, OSError) as exc:
                last = exc
                if not is_transient(exc):
                    raise
                # READONLY means waiting will not help this connection: step down now rather
                # than burning the whole retry budget on a mode that cannot work here.
                if _is_readonly(exc) and allow_fallback and self._downgrade_from_wal():
                    self._reopen()
                    return self._write(operation, attempts=attempts, allow_fallback=False)
                if attempt == attempts - 1:
                    break
                time.sleep(delay)
                delay = min(delay * 2, 1.0)

        # Out of retries. If WAL is what this filesystem cannot sustain, step down, reconnect
        # and start a fresh budget: the fallback changes the rules, and the other contenders
        # need time to notice the change too. A connection that has seen SQLITE_READONLY
        # during a journal-mode transition does not reliably recover, so it is replaced.
        if allow_fallback and self._downgrade_from_wal():
            self._reopen()
            return self._write(operation, attempts=attempts, allow_fallback=False)

        assert last is not None  # only reachable via the except branch
        raise last

    def _reopen(self) -> None:
        """Replace the connection, honouring whatever the journal-mode decision now is."""
        with self._lock:
            self._close_quietly()
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._configure(
                durability=self.durability,
                journal_mode=self.requested_journal_mode,
                busy_timeout_ms=self.busy_timeout_ms,
            )

    def reindex(self) -> int:
        """Rebuild the term index. Safe to run at any time.

        Exposed on the CLI because the tokenizer is the one part of this store
        expected to change as the product matures, and a stale index degrades recall
        silently rather than failing.
        """
        rows = self._write(lambda: self._conn.execute("SELECT id FROM memories").fetchall())

        def rebuild() -> None:
            self._conn.execute("DELETE FROM terms")
            for row in rows:
                length = self._index(row["id"], self._content_of(row["id"]))
                self._conn.execute(
                    "UPDATE memories SET doc_len = ? WHERE id = ?", (length, row["id"])
                )

        self._write(rebuild)
        return len(rows)

    def _content_of(self, memory_id: str) -> str:
        row = self._conn.execute(
            "SELECT content FROM memories WHERE id = ?", (memory_id,)
        ).fetchone()
        return row["content"] if row else ""

    # ---- basic CRUD ----

    def add(self, item: MemoryItem) -> MemoryItem:
        row = item.to_row()

        def insert() -> None:
            row["doc_len"] = self._index(item.id, item.content)
            cols = ", ".join(row)
            marks = ", ".join(f":{c}" for c in row)
            self._conn.execute(f"INSERT INTO memories ({cols}) VALUES ({marks})", row)

        self._write(insert)
        return item

    def add_with_attempt(
        self,
        item: MemoryItem,
        *,
        tenant: str,
        subject: str,
        source: str,
        scope: str,
        outcome: str,
        now: datetime,
    ) -> MemoryItem:
        """Insert a memory *and* its write-attempt record in one transaction.

        They are two rows describing one event, and writing them separately cost twice the
        commits. A commit on this filesystem costs a flat ~28ms regardless of `synchronous`
        (measured: `normal` was no faster than `full`, and a bare sqlite insert-and-commit
        ran at the same 36/s), so two commits per write halved throughput to 17 writes/second
        while one commit reaches 35.

        Atomicity is the more important half of the argument, though: with two transactions a
        crash between them leaves a memory that the ledger has no record of, and the ledger is
        what burst detection counts.

        Optional: a backend that does not implement this falls back to two transactions. The
        governor discovers it by attribute, the same way it discovers an optional ledger.
        """
        row = item.to_row()

        def insert() -> None:
            row["doc_len"] = self._index(item.id, item.content)
            cols = ", ".join(row)
            marks = ", ".join(f":{c}" for c in row)
            self._conn.execute(f"INSERT INTO memories ({cols}) VALUES ({marks})", row)
            self._conn.execute(
                "INSERT INTO write_attempts (tenant, subject, source, scope, outcome, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (tenant, subject or "", source, scope, outcome, now.isoformat()),
            )

        self._write(insert)
        return item

    def get(self, memory_id: str) -> MemoryItem | None:
        row = self._read(
            lambda: self._conn.execute(
                "SELECT * FROM memories WHERE id = ?", (memory_id,)
            ).fetchone()
        )
        return MemoryItem.from_row(row) if row else None

    def update(self, memory_id: str, **fields: Any) -> None:
        if not fields:
            return
        if "tags" in fields and not isinstance(fields["tags"], str):
            fields["tags"] = json.dumps(list(fields["tags"]), ensure_ascii=False)
        for key in ("created_at", "last_access", "expires_at"):
            if key in fields and isinstance(fields[key], datetime):
                fields[key] = iso(fields[key])

        def apply() -> None:
            if "content" in fields:
                # Content changed, so the inverted index must follow, or recall keeps
                # matching text that is no longer there.
                self._deindex(memory_id)
                fields["doc_len"] = self._index(memory_id, str(fields["content"]))
            sets = ", ".join(f"{k} = :{k}" for k in fields)
            cur = self._conn.execute(
                f"UPDATE memories SET {sets} WHERE id = :__id", {**fields, "__id": memory_id}
            )
            if cur.rowcount == 0:
                raise BackendError(f"No memory with id {memory_id!r}")

        self._write(apply)

    def delete(self, ids: Sequence[str]) -> list[str]:
        """Hard delete. Forgetting has to be real, or it cannot be proven to a regulator."""
        if not ids:
            return []

        def remove() -> None:
            marks = ", ".join("?" for _ in ids)
            self._conn.execute(f"DELETE FROM terms WHERE memory_id IN ({marks})", list(ids))
            self._conn.execute(f"DELETE FROM memories WHERE id IN ({marks})", list(ids))

        self._write(remove)
        return list(ids)

    def all_items(self, tenant: str | None = None) -> list[MemoryItem]:
        with self._lock:
            if tenant:
                rows = self._conn.execute(
                    "SELECT * FROM memories WHERE tenant = ? ORDER BY created_at", (tenant,)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM memories ORDER BY created_at"
                ).fetchall()
        return [MemoryItem.from_row(r) for r in rows]

    def count(self, tenant: str | None = None) -> int:
        with self._lock:
            if tenant:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM memories WHERE tenant = ?", (tenant,)
                ).fetchone()
            else:
                row = self._conn.execute("SELECT COUNT(*) AS n FROM memories").fetchone()
            return int(row["n"])

    # ---- BM25 retrieval ----

    def _index_statistics(
        self, tenant: str, query_terms: Sequence[str]
    ) -> tuple[int, float, dict[str, int]]:
        """Document count, average length and per-term document frequency.

        Computed over the whole tenant corpus, never over the authorised subset. See the
        module docstring: shared statistics are what keep the two retrieval paths from
        ranking differently.

        Both reads happen under a single lock acquisition on purpose. Taking the lock
        twice would let a concurrent write land in between, so the document frequencies
        would describe a different corpus than the document count, and BM25 would weight
        the terms against a state that never existed.
        """
        marks = ", ".join("?" for _ in query_terms)
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(AVG(doc_len), 0.0) AS avgdl"
                " FROM memories WHERE tenant = ? AND status = 'active'",
                (tenant,),
            ).fetchone()
            frequencies: dict[str, int] = {}
            if query_terms:
                frequency_rows = self._conn.execute(
                    f"SELECT t.term AS term, COUNT(*) AS df"
                    f" FROM terms t JOIN memories m ON m.id = t.memory_id"
                    f" WHERE t.term IN ({marks}) AND m.tenant = ? AND m.status = 'active'"
                    f" GROUP BY t.term",
                    [*query_terms, tenant],
                ).fetchall()
                frequencies = {r["term"]: int(r["df"]) for r in frequency_rows}
        return int(row["n"]), float(row["avgdl"] or 0.0), frequencies

    def _search(
        self,
        query: str,
        *,
        tenant: str,
        min_confidence: float,
        now: datetime,
        limit: int,
        min_score: float,
        allowed_scopes: Sequence[str] | None,
        offset: int = 0,
    ) -> list[tuple[MemoryItem, float]]:
        query_terms = sorted(tokens(query))
        if not query_terms:
            return []

        n_docs, avg_doc_len, df = self._index_statistics(tenant, query_terms)
        if n_docs == 0 or avg_doc_len <= 0 or not df:
            return []
        # Standard BM25 idf, floored at zero: a term present in every document
        # carries no information and must not be able to drag an irrelevant memory
        # into the candidate set.
        idf = {
            term: max(0.0, math.log(1.0 + (n_docs - freq + 0.5) / (freq + 0.5)))
            for term, freq in df.items()
        }
        idf = {term: weight for term, weight in idf.items() if weight > 0}
        if not idf:
            return []

        params: list[Any] = []
        for term, weight in idf.items():
            params.extend([term, weight])

        # Positional, in the order the placeholders appear in the SQL text below.
        params.extend([BM25_K1 + 1, BM25_K1, 1.0 - BM25_B, BM25_B, avg_doc_len])
        params.extend([tenant, min_confidence, now.isoformat()])

        scope_clause = ""
        if allowed_scopes is not None:
            if not allowed_scopes:
                return []
            scope_marks = ", ".join("?" for _ in allowed_scopes)
            scope_clause = f" AND m.scope IN ({scope_marks})"
            params.extend(allowed_scopes)

        params.extend([min_score, limit, offset])

        value_marks = ", ".join("(?, ?)" for _ in idf)
        sql = f"""
        WITH q(term, weight) AS (VALUES {value_marks})
        SELECT m.id AS id,
               SUM(q.weight * (t.tf * ?) / (t.tf + ? * (? + ? * m.doc_len / ?))) AS score
        FROM q
        JOIN terms t ON t.term = q.term
        JOIN memories m ON m.id = t.memory_id
        WHERE m.tenant = ? AND m.status = 'active'
          AND m.confidence >= ?
          AND (m.expires_at IS NULL OR m.expires_at > ?){scope_clause}
        GROUP BY m.id
        HAVING score > ?
        ORDER BY score DESC, m.id
        LIMIT ? OFFSET ?
        """
        with self._lock:
            scored = self._conn.execute(sql, params).fetchall()
            if not scored:
                return []
            # Fetch full rows in a second query rather than selecting m.* alongside an
            # aggregate, which relies on SQLite's bare-column tolerance.
            order = {row["id"]: float(row["score"]) for row in scored}
            marks = ", ".join("?" for _ in scored)
            rows = self._conn.execute(
                f"SELECT * FROM memories WHERE id IN ({marks})", list(order)
            ).fetchall()

        items = {row["id"]: MemoryItem.from_row(row) for row in rows}
        ranked = [(items[mid], score) for mid, score in order.items() if mid in items]
        ranked.sort(key=lambda pair: pair[1], reverse=True)
        return ranked

    def search_candidates(
        self,
        query: str,
        *,
        tenant: str,
        min_confidence: float,
        now: datetime,
        limit: int = 20,
        min_score: float = 0.0,
        offset: int = 0,
    ) -> list[tuple[MemoryItem, float]]:
        """No authorisation filter.

        Powers the "hit but refused" explainability report, and the paged scan in
        `post_filter` mode. `offset` exists so the caller can walk past a window that was
        entirely filled with memories the caller is not cleared for.
        """
        return self._search(
            query,
            tenant=tenant,
            min_confidence=min_confidence,
            now=now,
            limit=limit,
            min_score=min_score,
            allowed_scopes=None,
            offset=offset,
        )

    def search_allowed(
        self,
        query: str,
        *,
        tenant: str,
        allowed_scopes: Sequence[str],
        min_confidence: float,
        now: datetime,
        limit: int = 20,
        min_score: float = 0.0,
        offset: int = 0,
    ) -> list[tuple[MemoryItem, float]]:
        """Authorisation pushed into SQL. This is the path a large store must use."""
        return self._search(
            query,
            tenant=tenant,
            min_confidence=min_confidence,
            now=now,
            limit=limit,
            min_score=min_score,
            allowed_scopes=list(allowed_scopes),
            offset=offset,
        )

    # ---- maintenance helpers ----

    def active_by_subject(self, tenant: str, subject: str) -> list[MemoryItem]:
        rows = self._read(
            lambda: self._conn.execute(
                "SELECT * FROM memories WHERE tenant = ? AND subject = ? AND status = 'active'"
                " ORDER BY created_at",
                (tenant, subject),
            ).fetchall()
        )
        return [MemoryItem.from_row(r) for r in rows]

    def touch(self, ids: Sequence[str], now: datetime) -> None:
        if not ids:
            return
        marks = ", ".join("?" for _ in ids)
        params = [now.isoformat(), *ids]
        self._write(
            lambda: self._conn.execute(
                f"UPDATE memories SET last_access = ? WHERE id IN ({marks})", params
            )
        )

    # ---- write-attempt ledger ----

    def record_attempt(
        self,
        *,
        tenant: str,
        subject: str,
        source: str,
        scope: str,
        outcome: str,
        now: datetime,
    ) -> None:
        attempt = (
            tenant,
            subject or "",
            source,
            scope,
            outcome,
            now.isoformat(),
        )
        self._write(
            lambda: self._conn.execute(
                "INSERT INTO write_attempts (tenant, subject, source, scope, outcome, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                attempt,
            )
        )

    def count_attempts_since(self, *, tenant: str, subject: str, since: datetime) -> int:
        row = self._read(
            lambda: self._conn.execute(
                "SELECT COUNT(*) AS n FROM write_attempts"
                " WHERE tenant = ? AND subject = ? AND ts >= ?",
                (tenant, subject, since.isoformat()),
            ).fetchone()
        )
        return int(row["n"])

    def attempts(self, tenant: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if tenant:
                rows = self._conn.execute(
                    "SELECT * FROM write_attempts WHERE tenant = ? ORDER BY ts", (tenant,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM write_attempts ORDER BY ts").fetchall()
        return [dict(row) for row in rows]

    # ---- lifecycle ----

    def health(self) -> dict[str, Any]:
        """Cheap self-check, used by `amnesia verify` and by readiness probes."""
        with self._lock:
            integrity = self._conn.execute("PRAGMA integrity_check").fetchone()[0]
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            indexed = int(self._conn.execute("SELECT COUNT(*) FROM terms").fetchone()[0])
            stored = int(self._conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0])
            journal = self._conn.execute("PRAGMA journal_mode").fetchone()[0]
            synchronous = int(self._conn.execute("PRAGMA synchronous").fetchone()[0])
        return {
            "path": self.path,
            "schema_version": version,
            "integrity": integrity,
            "journal_mode": journal,
            "requested_journal_mode": self.requested_journal_mode,
            "synchronous": synchronous,
            "memories": stored,
            "indexed_terms": indexed,
            "index_fresh": indexed > 0 or stored == 0,
            "degradations": list(self.degradations),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
