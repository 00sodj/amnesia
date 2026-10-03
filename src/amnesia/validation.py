"""Input validation.

Every value that reaches the governor is checked before it can affect a decision.
This is not defensive programming for its own sake: a governance layer that coerces
bad input produces an audit record describing something that did not happen. If a
2MB document is silently truncated, or an unknown role is silently dropped, the log
becomes fiction -- and the log is the product.

Limits are deliberately generous. They exist to stop accidents and abuse, not to
second-guess a caller's data model.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .errors import ValidationError

MAX_CONTENT_BYTES = 256 * 1024
MAX_SUBJECT_LEN = 256
MAX_SOURCE_LEN = 128
MAX_TENANT_LEN = 128
MAX_OWNER_LEN = 256
MAX_TAG_LEN = 64
MAX_TAGS = 32
MAX_PRINCIPAL_ID_LEN = 256
MAX_ROLES = 16


def _require_str(value: Any, field: str, *, max_len: int, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string, got {type(value).__name__}")
    if not allow_empty and not value.strip():
        raise ValidationError(f"{field} must not be empty")
    if len(value) > max_len:
        raise ValidationError(f"{field} exceeds {max_len} characters (got {len(value)})")
    return value


def validate_write(
    *,
    content: Any,
    source: Any,
    tenant: Any,
    scope: Any,
    subject: Any = "",
    owner: Any = "",
    confidence: Any = 1.0,
    tags: Sequence[Any] = (),
) -> None:
    """Validate a write before any policy or detector sees it."""
    if not isinstance(content, str):
        raise ValidationError(f"content must be a string, got {type(content).__name__}")
    if not content.strip():
        raise ValidationError("content must not be empty")
    # Byte length, not character count: the limit exists to bound storage and the
    # audit trail, both of which are measured in bytes.
    size = len(content.encode("utf-8"))
    if size > MAX_CONTENT_BYTES:
        raise ValidationError(
            f"content is {size} bytes, above the {MAX_CONTENT_BYTES}-byte limit. "
            "Store a reference to the document, not the document."
        )

    _require_str(source, "source", max_len=MAX_SOURCE_LEN)
    _require_str(tenant, "tenant", max_len=MAX_TENANT_LEN, allow_empty=False)
    _require_str(scope, "scope", max_len=64, allow_empty=False)
    _require_str(subject, "subject", max_len=MAX_SUBJECT_LEN)
    _require_str(owner, "owner", max_len=MAX_OWNER_LEN)

    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValidationError(f"confidence must be a number, got {type(confidence).__name__}")
    if not 0.0 <= float(confidence) <= 1.0:
        raise ValidationError(f"confidence must be within [0, 1], got {confidence}")

    if tags is None:
        raise ValidationError("tags must be a sequence, got None")
    tags = list(tags)
    if len(tags) > MAX_TAGS:
        raise ValidationError(f"at most {MAX_TAGS} tags are allowed, got {len(tags)}")
    for tag in tags:
        _require_str(tag, "tag", max_len=MAX_TAG_LEN, allow_empty=False)


def validate_principal(principal: Any) -> None:
    """Validate an identity before it is used to authorise anything.

    An empty role list is rejected rather than defaulted: a principal with no roles
    would fall through clearance checks with level 0 and look like a refusal, which
    is a confusing way to be safe.
    """
    principal_id = getattr(principal, "id", None)
    tenant = getattr(principal, "tenant", None)
    roles = getattr(principal, "roles", None)

    _require_str(principal_id, "principal.id", max_len=MAX_PRINCIPAL_ID_LEN, allow_empty=False)
    _require_str(tenant, "principal.tenant", max_len=MAX_TENANT_LEN, allow_empty=False)

    if not isinstance(roles, (tuple, list)) or not roles:
        raise ValidationError("principal.roles must be a non-empty sequence")
    if len(roles) > MAX_ROLES:
        raise ValidationError(f"at most {MAX_ROLES} roles are allowed, got {len(roles)}")
    for role in roles:
        _require_str(role, "principal.role", max_len=MAX_TAG_LEN, allow_empty=False)


def validate_recall(*, query: Any, limit: Any, mode: Any) -> None:
    _require_str(query, "query", max_len=MAX_CONTENT_BYTES)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValidationError(f"limit must be an integer, got {type(limit).__name__}")
    if limit < 1 or limit > 1000:
        raise ValidationError(f"limit must be within [1, 1000], got {limit}")
    if mode not in ("post_filter", "pre_filter"):
        raise ValidationError(
            f"mode must be 'post_filter' or 'pre_filter', got {mode!r}"
        )
