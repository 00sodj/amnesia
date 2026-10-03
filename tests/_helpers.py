"""Shared test doubles.

Kept out of the test modules so more than one of them can use the same foreign backend.
pytest puts this directory on `sys.path`, so `import _helpers` works without making
`tests` a package.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from amnesia import MemoryItem
from amnesia.store import tokens


class DictBackend:
    """A deliberately different memory store: plain dicts, no SQL, no BM25.

    Implements only `MemoryBackend` -- no write-attempt ledger, no `health()` -- so it
    exercises the documented degradation paths as well as the seam itself.
    """

    def __init__(self) -> None:
        self._items: dict[str, MemoryItem] = {}

    def add(self, item: MemoryItem) -> MemoryItem:
        self._items[item.id] = item
        return item

    def get(self, memory_id: str) -> MemoryItem | None:
        return self._items.get(memory_id)

    def update(self, memory_id: str, **fields: Any) -> None:
        item = self._items[memory_id]
        for key, value in fields.items():
            setattr(item, key, value)

    def delete(self, ids: Sequence[str]) -> list[str]:
        for memory_id in ids:
            self._items.pop(memory_id, None)
        return list(ids)

    def all_items(self, tenant: str | None = None) -> list[MemoryItem]:
        return [item for item in self._items.values() if tenant is None or item.tenant == tenant]

    def count(self, tenant: str | None = None) -> int:
        return len(self.all_items(tenant))

    def active_by_subject(self, tenant: str, subject: str) -> list[MemoryItem]:
        return [
            item
            for item in self.all_items(tenant)
            if item.subject == subject and item.status == "active"
        ]

    def touch(self, ids: Sequence[str], now: datetime) -> None:
        for memory_id in ids:
            if memory_id in self._items:
                self._items[memory_id].last_access = now

    def _score(
        self,
        query: str,
        tenant: str,
        allowed_scopes: Sequence[str] | None,
        min_confidence: float,
        now: datetime,
        limit: int,
        offset: int = 0,
    ) -> list[tuple[MemoryItem, float]]:
        wanted = tokens(query)
        scored: list[tuple[MemoryItem, float]] = []
        for item in self.all_items(tenant):
            if item.status != "active" or item.confidence < min_confidence:
                continue
            if item.expires_at and item.expires_at <= now:
                continue
            if allowed_scopes is not None and item.scope not in allowed_scopes:
                continue
            score = len(wanted & tokens(item.content))
            if score:
                scored.append((item, float(score)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[offset : offset + limit]

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
        return self._score(query, tenant, None, min_confidence, now, limit, offset)

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
        return self._score(
            query, tenant, list(allowed_scopes), min_confidence, now, limit, offset
        )

    def close(self) -> None:
        self._items.clear()
