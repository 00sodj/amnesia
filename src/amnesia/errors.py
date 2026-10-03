"""Exception hierarchy.

A governance layer that fails silently is worse than no governance layer: callers
get an answer and assume it was authorised. So every failure mode that could
degrade a guarantee has a named type, and none of them are `Exception`.

    AmnesiaError
    ├── ValidationError   bad input from the caller (fix your call)
    ├── PolicyError       the policy file is wrong or contradicts itself
    ├── BackendError      the memory store cannot honour its contract
    └── IntegrityError    a guarantee was about to be broken; refuses to proceed
"""

from __future__ import annotations

import sqlite3


class AmnesiaError(Exception):
    """Base class. Catch this to handle anything this package raises."""


# Retried rather than raised: access denied and sharing violation. On Windows a file another
# handle has open reads as "permission denied", and that is frequently transient -- antivirus,
# the search indexer, a process deleting SQLite's journal file. EPERM and ENOSPC are excluded
# on purpose: they do not clear if you wait, so retrying would only delay the error.
TRANSIENT_ACCESS_ERRNOS = frozenset({5, 13, 32})


def is_transient(exc: BaseException) -> bool:
    """Will this clear if you wait?

    Shared by the store and by the audit log, because one governed operation touches both and a
    transient failure in either one fails the whole thing. It was the audit log that kept
    failing: `PermissionError(13)` reached the caller un-retried and a governed write was lost.

    Three shapes qualify:

    - **BUSY / LOCKED** -- somebody else holds the lock and will release it.
    - **READONLY** -- in WAL mode, this connection cannot write while the journal mode is
      changed underneath it. Not the same as BUSY: waiting does not help this connection, so
      `_write` reacts immediately instead of spending its whole retry budget on it.
    - **OSError with a transient access errno** -- see `TRANSIENT_ACCESS_ERRNOS`.
    """
    if isinstance(exc, OSError) and not isinstance(exc, sqlite3.Error):
        return exc.errno in TRANSIENT_ACCESS_ERRNOS
    return any(marker in str(exc).lower() for marker in ("locked", "busy", "readonly"))


class ValidationError(AmnesiaError, ValueError):
    """The caller passed something that cannot be governed.

    Raised rather than coerced: silently truncating a 2MB memory or dropping an
    unknown role would make the audit trail describe something that did not happen.
    """


class PolicyError(AmnesiaError, ValueError):
    """The policy file is malformed, or a rule contradicts another rule.

    Refuse to start. Running with a policy nobody intended is the failure mode this
    exception exists to prevent.
    """


class BackendError(AmnesiaError, RuntimeError):
    """The memory store cannot satisfy the `MemoryBackend` contract."""


class IntegrityError(AmnesiaError, RuntimeError):
    """Proceeding would break a guarantee the product claims to make.

    Reserved for cases where continuing is worse than failing: a deletion whose
    proof cannot be computed, an audit event that cannot be written.
    """
