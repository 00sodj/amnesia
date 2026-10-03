"""The seam that makes "sits in front of the memory store you already run" real.

Amnesia does not want to become your memory store. It wants to be the thing your
memory store sits behind. That only works if the store is swappable, so this module
defines the contract.

**Honest scope note.** What ships here is the extension point, the reference
implementation (`store.MemoryStore`) and a test proving a foreign backend can be
dropped in. Shipping adapters for specific third-party stores -- `hindsight`,
`ai-memory`, `company-brain` -- is deliberately *not* included: each one needs that
project's real API surface, and guessing at it would produce adapter code that
looks finished and has never once executed. A defined seam plus a test is worth
more than a fabricated integration.

Two protocols, because they have different bars:

  - `MemoryBackend` is what a memory store must provide. Any store that can be
    wrapped by an adapter can satisfy it.
  - `WriteAttemptLedger` is optional. It is governance telemetry, not storage, and
    requiring it of every backend would make adapters harder to write for no good
    reason. Without it, burst detection falls back to an in-process ledger.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from .models import MemoryItem


@runtime_checkable
class MemoryBackend(Protocol):
    """What the governor needs from a memory store.

    Deliberately narrow. In particular there is no `search(query)` that returns
    ranked results with authorization already applied, because the two retrieval
    paths are the whole point: `search_candidates` exists to report what was
    *withheld*, and a backend that cannot answer that cannot support the
    explainability guarantee.
    """

    def add(self, item: MemoryItem) -> MemoryItem: ...

    def get(self, memory_id: str) -> MemoryItem | None: ...

    def update(self, memory_id: str, **fields: Any) -> None: ...

    def delete(self, ids: Sequence[str]) -> list[str]: ...

    def all_items(self, tenant: str | None = None) -> list[MemoryItem]: ...

    def count(self, tenant: str | None = None) -> int: ...

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
    ) -> list[tuple[MemoryItem, float]]: ...

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
    ) -> list[tuple[MemoryItem, float]]: ...

    def active_by_subject(self, tenant: str, subject: str) -> list[MemoryItem]: ...

    def touch(self, ids: Sequence[str], now: datetime) -> None: ...

    def close(self) -> None: ...


@runtime_checkable
class WriteAttemptLedger(Protocol):
    """Every write attempt, including the rejected ones.

    A store that only records successes cannot show a burst of *refused* writes,
    which is the signature of someone probing the gate -- so this cannot be
    reconstructed from the memory table after the fact.
    """

    def record_attempt(
        self,
        *,
        tenant: str,
        subject: str,
        source: str,
        scope: str,
        outcome: str,
        now: datetime,
    ) -> None: ...

    def count_attempts_since(self, *, tenant: str, subject: str, since: datetime) -> int: ...


class InMemoryLedger:
    """Fallback for backends that do not implement `WriteAttemptLedger`.

    Degraded but not silent: burst detection still works for the lifetime of the
    process, and `MemoryGovernor` records the degradation in the audit stream so an
    operator can tell the difference between "no burst" and "we cannot see bursts".
    """

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []

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
        self._rows.append(
            {
                "tenant": tenant,
                "subject": subject or "",
                "source": source,
                "scope": scope,
                "outcome": outcome,
                "ts": now,
            }
        )

    def count_attempts_since(self, *, tenant: str, subject: str, since: datetime) -> int:
        return sum(
            1
            for row in self._rows
            if row["tenant"] == tenant and row["subject"] == subject and row["ts"] >= since
        )

    def attempts(self) -> list[dict[str, Any]]:
        return list(self._rows)


def resolve_ledger(backend: MemoryBackend) -> WriteAttemptLedger:
    """Use the backend's own ledger when it has one, otherwise fall back."""
    if isinstance(backend, WriteAttemptLedger):
        return backend
    return InMemoryLedger()
