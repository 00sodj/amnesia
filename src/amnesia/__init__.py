"""Amnesia -- a governance layer for agent memory.

Most memory projects answer "how do we remember more?". Amnesia answers the other
half: what should never be stored, who is allowed to see it, and when it should be
forgotten.

Quick orientation:

    MemoryGovernor     the only entry point you normally need
    PolicyEngine       "who can see what", as reviewable configuration
    PoisonDetector     pattern attacks a per-memory gate cannot see
    MemoryStore        reference backend (SQLite + BM25)
    MemoryBackend      protocol other stores implement to sit behind this layer
    AuditLog           append-only evidence, including refusals
    Maintenance        supersession, decay and physical deletion
"""

from .audit import AuditLog, PolicyStampedAudit
from .backend import InMemoryLedger, MemoryBackend, WriteAttemptLedger, resolve_ledger
from .errors import AmnesiaError, BackendError, IntegrityError, PolicyError, ValidationError
from .expiry import Maintenance, SweepReport
from .governor import CANDIDATE_LIMIT, MemoryGovernor
from .models import MemoryItem, Principal, parse_iso, utcnow
from .poison import Finding, PoisonDetector, PoisonReport
from .policy import PolicyDecision, PolicyEngine, diff_configs
from .report import build_report, render_markdown
from .store import MemoryStore, tokens
from .validation import validate_principal, validate_recall, validate_write

__version__ = "0.2.0"

__all__ = [
    "CANDIDATE_LIMIT",
    "AmnesiaError",
    "AuditLog",
    "BackendError",
    "Finding",
    "InMemoryLedger",
    "IntegrityError",
    "Maintenance",
    "MemoryBackend",
    "MemoryGovernor",
    "MemoryItem",
    "MemoryStore",
    "PoisonDetector",
    "PoisonReport",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyError",
    "PolicyStampedAudit",
    "Principal",
    "SweepReport",
    "ValidationError",
    "WriteAttemptLedger",
    "__version__",
    "build_report",
    "diff_configs",
    "parse_iso",
    "render_markdown",
    "resolve_ledger",
    "tokens",
    "utcnow",
    "validate_principal",
    "validate_recall",
    "validate_write",
]
