"""Audit log.

The least glamorous layer in the project, and the one that decides enterprise
deals. Every write, allow, denial and deletion must leave a tamper-evident trail.

Denied recalls are recorded too. "What the agent wanted to say but was not
allowed to" is more interesting evidence than what it did say.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

from .chain import GENESIS, ChainStatus, digest, verify
from .errors import BackendError, is_transient
from .models import utcnow

_TAIL_BLOCK = 4096


def _tail_link(handle: BinaryIO) -> tuple[int, str]:
    """Read the last entry and return the `(seq, prev)` the next one should link to.

    Read backwards in blocks rather than reading the file: the log is append-only and grows
    without bound, and this runs on every governed operation.

    Returns `(1, GENESIS)` when there is nothing to link to — an empty log, or a tail that
    cannot be parsed because a previous writer died mid-line. Starting a fresh segment is the
    honest response to an unreadable tail: the alternative is refusing to audit, and an
    unaudited write is the worse outcome. The boundary it writes is visible to `chain.verify`,
    which is what stops it being a way to hide an edit.
    """
    handle.seek(0, os.SEEK_END)
    remaining = handle.tell()
    if remaining == 0:
        return 1, GENESIS

    buffer = b""
    while remaining > 0 and buffer.count(b"\n") < 2:
        step = min(_TAIL_BLOCK, remaining)
        remaining -= step
        handle.seek(remaining)
        buffer = handle.read(step) + buffer

    lines = [line for line in buffer.split(b"\n") if line.strip()]
    if not lines:
        return 1, GENESIS
    try:
        last = json.loads(lines[-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 1, GENESIS

    seq = last.get("seq")
    link = last.get("hash")
    if not isinstance(seq, int) or not isinstance(link, str):
        # The last entry predates chaining. Start a segment; `chain.verify` reports the
        # unchained prefix rather than pretending it was verified.
        return 1, GENESIS
    return seq + 1, link


class AuditLog:
    """Append-only JSONL stream.

    Deliberately not a database: it should stay greppable, diffable and
    archivable by whatever the customer already uses.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        # Set by `entries()`; also here so it is readable before the first read.
        self.unreadable_lines = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BackendError(
                f"Cannot create the audit log directory {self.path.parent}: {exc}"
            ) from exc

        # Checked here rather than discovered on the first append. Without this, pointing
        # --audit at a directory raised a bare `PermissionError` from inside pathlib on the
        # first write, several layers below anything that could explain it, and the CLI does not
        # catch that type -- so the operator got a traceback for a configuration mistake.
        if self.path.exists() and not self.path.is_file():
            raise BackendError(
                f"Cannot open audit log at {str(self.path)!r}: it exists but is not a file. "
                "Point --audit at a file, or at a path that does not exist yet."
            )

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one entry, chained to the one before it.

        Retried on a transient access error, because this is on the critical path of every
        governed operation: a host briefly refusing to open the file used to take the whole
        `remember` down with it. Not swallowed: if the retries are exhausted the error is
        raised, because an audit entry that silently goes missing is a worse outcome than a
        failed write.

        The whole read-tail-then-append happens under an exclusive lock, and that is not
        optional. Chaining needs the previous entry's hash, which makes appending a
        read-modify-write: without the lock, two processes read the same predecessor and build
        two entries on top of it, and the resulting log is *indistinguishable from tampering*
        when verified. A tamper-evident log that cries wolf under ordinary concurrent use is
        worse than no chain at all, and ten concurrent CLI processes is an ordinary load.
        """
        entry = {"ts": utcnow().isoformat(), "event": event, **fields}
        delay = 0.02
        for attempt in range(8):
            try:
                with self._locked_append() as handle:
                    seq, prev = _tail_link(handle)
                    entry["seq"] = seq
                    entry["prev"] = prev
                    entry["hash"] = digest(seq, prev, entry)
                    handle.seek(0, os.SEEK_END)
                    handle.write((json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
                return entry
            except OSError as exc:
                if attempt == 7 or not is_transient(exc):
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.5)
        raise AssertionError("unreachable")  # pragma: no cover

    @contextmanager
    def _locked_append(self) -> Iterator[BinaryIO]:
        """Open the log for appending and hold an exclusive lock on it.

        `msvcrt` on Windows, `fcntl` elsewhere — both are stdlib, and this is the only place the
        project needs a cross-process lock. The lock is advisory, which is enough here: every
        writer goes through this method.
        """
        handle = self.path.open("a+b")
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                # mypy resolves `fcntl` against Windows stubs, where it has no attributes;
                # this branch is unreachable on Windows.
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]
            try:
                yield handle
            finally:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
        finally:
            handle.close()

    def chain_status(self) -> ChainStatus:
        """Verify the log's hash chain. See `amnesia.chain` for what is and is not proven."""
        status = verify(self.entries())
        if self.unreadable_lines:
            status = ChainStatus(
                chained=status.chained,
                unchained=status.unchained,
                breaks=status.breaks,
                first_break_index=status.first_break_index,
                unreadable=self.unreadable_lines,
            )
        return status

    # ---- semantic wrappers, so event names stay consistent ----

    def write_decision(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.write", **f)

    def read_decision(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.read", **f)

    def recall_denied(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.recall_denied", **f)

    def forget(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.forget", **f)

    def sweep(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.sweep", **f)

    # ---- queries ----

    def entries(self) -> Iterator[dict[str, Any]]:
        """Yield every entry that can be parsed, and count the ones that cannot.

        Skipping rather than raising, because the log is a plain file that customers grep and
        archive, and a writer killed mid-append leaves a half-written line behind. Raising on it
        took down `report`, `verify`, `explain` and `flagged` at once — one damaged line anywhere
        in the file made the whole trail unreadable, which is the opposite of what an evidence
        store should do.

        The count lands on `unreadable_lines` so a caller can report on a subset *knowingly*
        rather than quietly. A damaged line normally shows up as a gap or a broken link in the
        hash chain too, and that is the stronger signal.
        """
        self.unreadable_lines = 0
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    self.unreadable_lines += 1

    def for_memory(self, memory_id: str) -> list[dict[str, Any]]:
        """The full lifecycle of one memory: who wrote it, who asked, how often it was refused."""
        return [e for e in self.entries() if e.get("memory_id") == memory_id]

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        """The last n entries, read backwards from the end of the file.

        Reading the whole log to return twenty lines is fine until it is not. A
        long-running deployment accumulates entries without bound, and `tail` is exactly
        what an operator reaches for when the file has grown large. Splitting on the byte
        value of the newline is safe for UTF-8: a newline byte cannot occur inside a
        multi-byte character.
        """
        if n <= 0 or not self.path.exists():
            return []
        block = 64 * 1024
        with self.path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            remaining = handle.tell()
            buffer = b""
            # Keep growing the window until it holds more than n newlines, so the first
            # line is guaranteed to be complete.
            while remaining > 0 and buffer.count(b"\n") <= n:
                step = min(block, remaining)
                remaining -= step
                handle.seek(remaining)
                buffer = handle.read(step) + buffer
        lines = [line for line in buffer.split(b"\n") if line.strip()]
        # Same tolerance as `entries()`: a damaged line is skipped, not raised on. `audit --tail`
        # is what an operator reaches for *while* something is wrong, so it is the last thing
        # that should refuse to run.
        out: list[dict[str, Any]] = []
        for raw in lines[-n:]:
            try:
                out.append(json.loads(raw.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        return out


class PolicyStampedAudit:
    """Wraps an `AuditLog` and stamps every entry with the policy revision in force.

    Centralised rather than passed at each call site for a specific reason: there are
    more than a dozen places that write audit events, and each one remembering to
    include the revision is a chance to forget. An audit record that cannot say which
    policy governed the decision is much weaker evidence -- "we were authorised to do
    that" is unanswerable if permissions changed since.

    Delegates everything else, so it is a drop-in for `AuditLog`.
    """

    def __init__(self, inner: AuditLog, revision_provider: Any):
        self._inner = inner
        self._revision_provider = revision_provider

    @property
    def inner(self) -> AuditLog:
        return self._inner

    @property
    def path(self) -> Path:
        return self._inner.path

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        fields.setdefault("policy_revision", self._revision_provider())
        return self._inner.record(event, **fields)

    # Semantic wrappers must go through this class's `record`, not the inner one.
    def write_decision(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.write", **f)

    def read_decision(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.read", **f)

    def recall_denied(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.recall_denied", **f)

    def forget(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.forget", **f)

    def sweep(self, **f: Any) -> dict[str, Any]:
        return self.record("memory.sweep", **f)

    def entries(self) -> Iterator[dict[str, Any]]:
        return self._inner.entries()

    def for_memory(self, memory_id: str) -> list[dict[str, Any]]:
        return self._inner.for_memory(memory_id)

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        return self._inner.tail(n)

    def chain_status(self) -> ChainStatus:
        return self._inner.chain_status()
