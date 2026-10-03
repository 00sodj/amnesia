"""Core data types: who is asking (Principal) and what was remembered (MemoryItem)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    """Always timezone-aware UTC, so retention maths never drifts with the host clock."""
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def parse_iso(value: str | None) -> datetime | None:
    """Parse a stored timestamp, or `None` if it is not one.

    Returning `None` is what the signature already promises, and every call site relies on it:
    two read database rows, one reads audit entries. Raising instead was a real defect -- a
    hand-edited audit log with a single malformed timestamp took down the entire compliance
    report, and the report is the artifact you hand to an auditor. It should say what it can
    read, not refuse to be produced.

    A caller that needs to *reject* bad input should validate before calling; `cli._date` does
    exactly that and reports the offending value.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Principal:
    """The entity asking the question.

    The central design decision: capability comes from *identity*, not from the
    question. The same memory can resolve to completely different answers for an
    employee and for HR. That is the layer almost every memory store is missing.
    """

    id: str
    tenant: str
    roles: tuple[str, ...] = ("employee",)

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass
class MemoryItem:
    """A single governed memory.

    Beyond its content, a memory must carry four governance labels: source,
    access scope, confidence and expiry. Drop any one of them and the audit and
    forgetting guarantees downstream become impossible to honour.
    """

    content: str
    source: str
    tenant: str
    scope: str
    owner: str
    subject: str = ""
    confidence: float = 1.0
    tags: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    last_access: datetime | None = None
    expires_at: datetime | None = None
    status: str = "active"
    superseded_by: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # ---- serialisation ----

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "source": self.source,
            "tenant": self.tenant,
            "scope": self.scope,
            "owner": self.owner,
            "subject": self.subject,
            "confidence": float(self.confidence),
            "tags": json.dumps(list(self.tags), ensure_ascii=False),
            "created_at": iso(self.created_at),
            "last_access": iso(self.last_access),
            "expires_at": iso(self.expires_at),
            "status": self.status,
            "superseded_by": self.superseded_by,
        }

    @classmethod
    def from_row(cls, row: Any) -> MemoryItem:
        return cls(
            id=row["id"],
            content=row["content"],
            source=row["source"],
            tenant=row["tenant"],
            scope=row["scope"],
            owner=row["owner"],
            subject=row["subject"] or "",
            confidence=row["confidence"],
            tags=tuple(json.loads(row["tags"] or "[]")),
            created_at=parse_iso(row["created_at"]) or utcnow(),
            last_access=parse_iso(row["last_access"]),
            expires_at=parse_iso(row["expires_at"]),
            status=row["status"],
            superseded_by=row["superseded_by"],
        )

    # ---- read-only views ----

    def public_view(self) -> dict[str, Any]:
        """The shape handed to the agent: content plus provenance, no internals."""
        return {
            "id": self.id,
            "content": self.content,
            "scope": self.scope,
            "source": self.source,
            "subject": self.subject,
            "confidence": round(self.confidence, 2),
            "created_at": iso(self.created_at),
        }
