"""The policy engine: "who can see what", lifted out of application code into
configuration that can be reviewed, diffed and audited.

This is Amnesia's core bet. If authorization is scattered across business logic,
nobody can ever answer "why did this agent say that?".
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from . import pii
from .errors import PolicyError, ValidationError
from .models import MemoryItem, Principal, utcnow
from .poison import PoisonReport

UNVERSIONED = "unversioned"


def shipped_policy_path() -> Path | None:
    """The policy that ships inside the package, if it is present.

    It lives *inside* the package rather than beside it so that a real (non-editable)
    install has one. An install with no policy file falls back to the built-in defaults,
    which is a different permission model -- precisely the silent divergence this project
    exists to prevent.

    Resolved from `__file__`, so it works for editable and normal filesystem installs; a
    zipimport install would not have a real path, but such an install could not use the
    SQLite store either.
    """
    candidate = Path(__file__).resolve().parent / "policies" / "default.yaml"
    return candidate if candidate.is_file() else None


def resolve_policy_path(explicit: str | Path | None = None) -> Path | None:
    """Locate the policy file the same way from every entry point.

    Precedence: an explicit path, then `$AMNESIA_POLICY`, then the shipped default.

    This function exists because the CLI and the MCP server used to disagree: the server
    fell back to the shipped file, the CLI to the built-in defaults. Two entry points, two
    permission models, and nothing to tell you which one you were running -- which showed
    up in the audit log as a spurious "permissions changed mid-window" warning when a user
    passed `--policy` on some commands and not on others.

    Returns None only when none of the three exist, in which case the built-in defaults are
    used deliberately.
    """
    if explicit:
        return Path(explicit)
    from_env = os.environ.get("AMNESIA_POLICY")
    if from_env:
        return Path(from_env)
    return shipped_policy_path()


@dataclass(frozen=True)
class PolicyDecision:
    """One admission decision.

    `reason` must be readable by a human -- it is written verbatim to the audit
    log and is what a compliance reviewer will quote back at you.

    `code` is the machine-readable twin of `reason`. Grouping refusals for a
    compliance report must not depend on parsing human prose: the moment someone
    rewords a message, every historical report silently changes meaning.
    """

    allow: bool
    reason: str
    transformed: str | None = None
    flags: tuple[str, ...] = ()
    code: str = ""

    def __bool__(self) -> bool:  # lets callers write `if decision:`
        return self.allow

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "code": self.code,
            "reason": self.reason,
            "flags": list(self.flags),
        }


DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "roles": {
        "contractor": {"clearance": 1},
        "employee": {"clearance": 1},
        "manager": {"clearance": 2},
        "hr": {"clearance": 3},
        "admin": {"clearance": 4},
    },
    "scopes": {
        "personal": {"min_clearance": 1, "deletable": True},
        "project": {"min_clearance": 1, "deletable": True},
        "confidential": {"min_clearance": 2, "deletable": False},
        # Must stay in step with policies/default.yaml. When these two disagreed, the
        # same permission question got two different answers depending only on how the
        # engine was constructed -- which is exactly the kind of silent divergence a
        # governance layer cannot afford.
        "hr_only": {
            "min_clearance": 3,
            "deletable": False,
            "deny_roles": ["contractor", "employee"],
        },
    },
    "write": {
        "require_source": True,
        "detect_pii": True,
        "reject_on": ["secret"],
        "redact_on": ["email", "phone", "national_id", "ipv4"],
        "default_scope": "project",
        "min_confidence": 0.0,
        "max_confidence": 1.0,
        "ttl_days": {"default": 180, "personal": 90, "confidential": 365},
    },
    "read": {
        "require_same_tenant": True,
        "min_confidence": 0.3,
        "deny_if_superseded": True,
        "deny_expired": True,
        # BM25 score floor. 0.0 keeps any positive match; raise it to trade recall
        # for precision once you have real query logs to calibrate against.
        "min_score": 0.0,
    },
    "poison": {
        "enabled": True,
        # Severity -> action. "reject" blocks the write, "flag" stores it with a tag.
        # Which one is right is a judgement about your environment, not about the
        # content, so it belongs in configuration.
        "on_high": "reject",
        "on_medium": "flag",
        "on_low": "flag",
        "burst_threshold": 5,
        "burst_window_seconds": 600,
        # Empty means "trust has not been declared yet" and disables the two
        # provenance checks, rather than flagging every write out of the box.
        "trusted_sources": [],
        "trusted_required_scopes": [],
    },
}


class PolicyEngine:
    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config: dict[str, Any] = _deep_merge(DEFAULT_CONFIG, dict(config or {}))
        # Provenance of the policy itself. Populated by from_yaml(); without it a
        # permission change cannot be attributed to a file revision.
        self.source_path: Path | None = None
        self.fingerprint: str | None = None
        self._validate()

    # ---- construction ----

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        source = Path(path)
        if not source.is_file():
            # A typo in --policy otherwise surfaces as a bare FileNotFoundError from deep
            # inside pathlib, which reads as a crash rather than as "you named a file that
            # does not exist".
            raise PolicyError(f"Policy file not found: {source}")
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"Cannot read policy file {source}: {exc}") from exc
        raw = yaml.safe_load(text) or {}
        if not isinstance(raw, dict):
            raise PolicyError(f"Policy file must be a YAML mapping: {path}")
        engine = cls(raw)
        engine.source_path = source
        engine.fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return engine

    def _validate(self) -> None:
        for scope, spec in self.config["scopes"].items():
            if "min_clearance" not in spec:
                raise PolicyError(f"Scope '{scope}' is missing min_clearance")
        for level in ("high", "medium", "low"):
            action = self.config.get("poison", {}).get(f"on_{level}", "flag")
            if action not in ("reject", "flag", "allow"):
                raise PolicyError(
                    f"poison.on_{level} must be one of reject/flag/allow, got '{action}'"
                )

    # ---- lookups ----

    @property
    def scopes(self) -> Mapping[str, Any]:
        return self.config["scopes"]

    @property
    def revision(self) -> str:
        """Human-assigned label for this policy revision, e.g. "2026-09-29.2".

        The fingerprint proves *that* the file changed; the revision is what a
        reviewer can point at in a change ticket.

        Returns UNVERSIONED when the engine was built from the built-in defaults rather
        than a file. That is a real and distinguishable state, not a missing value: it
        means the decisions made under this engine were not governed by any policy file.
        """
        return str(self.config.get("revision", UNVERSIONED))

    @property
    def poison_config(self) -> Mapping[str, Any]:
        return self.config.get("poison", {})

    def scope_spec(self, scope: str) -> dict[str, Any]:
        spec = self.scopes.get(scope)
        if spec is None:
            raise PolicyError(f"Unknown scope '{scope}'. Available: {sorted(self.scopes)}")
        return dict(spec)

    def clearance_for(self, principal: Principal) -> int:
        """A principal may hold several roles; the highest clearance wins."""
        levels = [
            int(self.config["roles"].get(role, {}).get("clearance", 0))
            for role in principal.roles
        ]
        return max(levels) if levels else 0

    def unknown_roles(self, principal: Principal) -> list[str]:
        """Roles this policy does not define.

        Deliberately not an error: a deployment may add roles before the policy that defines
        them is loaded, and failing closed is the safe direction. But the fact has to be
        *visible*. An unrecognised role resolves to clearance 0, so a typo like
        `--roles empolyee` presents as "the policy denies me" -- and during an incident that
        is the wrong thing to be debugging.
        """
        return [role for role in principal.roles if role not in self.config["roles"]]

    def ttl_days_for(self, scope: str) -> int | None:
        ttl = self.config["write"].get("ttl_days", {})
        return ttl.get(scope, ttl.get("default"))

    def expires_at_for(self, scope: str, now: datetime | None = None) -> datetime | None:
        days = self.ttl_days_for(scope)
        return None if not days else (now or utcnow()) + timedelta(days=int(days))

    def readable_scopes(self, principal: Principal) -> list[str]:
        """Used for pushing filters down into retrieval: every scope this principal may touch."""
        level = self.clearance_for(principal)
        return [s for s, spec in self.scopes.items() if level >= int(spec["min_clearance"])]

    def is_deletable(self, scope: str) -> bool:
        return bool(self.scope_spec(scope).get("deletable", False))

    # ---- write gate ----

    def evaluate_write(
        self,
        *,
        content: str,
        source: str,
        scope: str,
        confidence: float = 1.0,
    ) -> PolicyDecision:
        """Codes matter as much here as in the read gate.

        A compliance report that renders every write rejection as "unspecified" tells the
        reader nothing: "we refused 40 writes" is not reviewable, "we refused 40 writes
        because they contained credentials" is. Every branch therefore carries a code.
        """
        rules = self.config["write"]

        if rules.get("require_source", True) and not (source or "").strip():
            return PolicyDecision(
                False,
                "Missing source: a memory without provenance cannot be stored",
                code="missing_source",
            )

        if not (content or "").strip():
            return PolicyDecision(False, "Content is empty", code="empty_content")

        self.scope_spec(scope)  # raises on an undefined scope

        floor = float(rules.get("min_confidence", 0.0))
        if confidence < floor:
            return PolicyDecision(
                False,
                f"Confidence {confidence:.2f} is below the write floor {floor:.2f}",
                code="low_confidence",
            )

        flags: list[str] = []
        transformed = content

        if rules.get("detect_pii", True):
            found = pii.scan(content)
            blocked = [k for k in found.kinds if k in rules.get("reject_on", [])]
            if blocked:
                return PolicyDecision(
                    False,
                    f"Blocked content detected: {', '.join(blocked)} "
                    f"(a credential can never be un-learned once it is stored)",
                    flags=tuple(blocked),
                    code="blocked_content",
                )
            to_redact = [k for k in found.kinds if k in rules.get("redact_on", [])]
            if to_redact:
                transformed = found.redacted
                flags.append("redacted:" + ",".join(to_redact))

        if transformed != content:
            return PolicyDecision(
                True, "Stored (redacted)", transformed, tuple(flags), code="stored_redacted"
            )
        return PolicyDecision(True, "Stored", transformed, tuple(flags), code="stored")

    def normalize_scope(self, scope: str | None) -> str:
        """Resolve the scope a write will land in.

        `None` means the caller did not choose one, and the policy's default applies. An empty
        string is **not** the same thing: it means a caller tried to supply a scope and failed —
        an unset shell variable, an empty form field, an MCP argument dropped in transit. This
        used to be `scope or default`, which silently promoted that to `project` and placed a
        memory the caller meant to restrict where everyone could read it. For a governance layer
        the difference between "unspecified" and "supplied as nothing" is the whole point.
        """
        if scope is None:
            return str(self.config["write"].get("default_scope", "project"))
        if not scope.strip():
            default = self.config["write"].get("default_scope", "project")
            raise ValidationError(
                f"scope was supplied but empty; omit it to accept the default ({default})"
            )
        return scope

    # ---- read gate ----

    def evaluate_read(
        self,
        item: MemoryItem,
        principal: Principal,
        *,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Cheap hard conditions first, expensive authorization last, short-circuiting.

        Order matters for more than performance: the reason returned is what the
        user and the auditor will see, so it should point at the most specific
        rule that fired.
        """
        rules = self.config["read"]
        now = now or utcnow()

        if rules.get("require_same_tenant", True) and item.tenant != principal.tenant:
            return PolicyDecision(
                False,
                f"Tenant mismatch: memory belongs to '{item.tenant}', "
                f"principal belongs to '{principal.tenant}'",
                code="tenant_mismatch",
            )

        if item.status == "deleted":
            return PolicyDecision(False, "Memory has been deleted", code="deleted")

        if rules.get("deny_if_superseded", True) and item.status == "superseded":
            return PolicyDecision(
                False, "Memory was superseded by a newer version", code="superseded"
            )

        if item.status != "active":
            return PolicyDecision(
                False,
                f"Memory status is '{item.status}' and does not participate in recall",
                code="not_active",
            )

        if rules.get("deny_expired", True) and item.expires_at and item.expires_at <= now:
            return PolicyDecision(
                False,
                f"Memory expired on {item.expires_at.date().isoformat()}",
                code="expired",
            )

        floor = float(rules.get("min_confidence", 0.0))
        if item.confidence < floor:
            return PolicyDecision(
                False,
                f"Confidence {item.confidence:.2f} is below the read floor {floor:.2f}",
                code="low_confidence",
            )

        spec = self.scope_spec(item.scope)
        need = int(spec["min_clearance"])
        barred = set(spec.get("deny_roles") or ())

        # `deny_roles` removes a role from consideration; it does not veto the principal.
        #
        # As a veto it made the two rules disagree in direction: clearance was the maximum
        # over the principal's roles, while the role bar was any-match. Somebody who was both
        # an employee and HR was therefore refused HR records *because* of the employee role
        # -- holding two roles left them less able to read than holding one. Effective
        # clearance is now computed from the roles that are not barred, which is what "an
        # explicit bar that survives a clearance change" was meant to mean.
        effective_roles = [role for role in principal.roles if role not in barred]
        if not effective_roles:
            return PolicyDecision(
                False,
                f"Denied: every role held ({'/'.join(principal.roles)}) is explicitly "
                f"blocked from scope '{item.scope}'",
                code="role_denied",
            )

        level = max(
            int(self.config["roles"].get(role, {}).get("clearance", 0))
            for role in effective_roles
        )
        if level < need:
            roles = "/".join(principal.roles) or "no roles"
            return PolicyDecision(
                False,
                f"Insufficient clearance: scope '{item.scope}' requires clearance >= {need}, "
                f"but '{principal.id}' ({roles}) has {level}",
                code="insufficient_clearance",
            )

        return PolicyDecision(True, "Allowed", code="allowed")

    # ---- poisoning verdict ----

    def evaluate_poison(self, report: PoisonReport | None) -> PolicyDecision:
        """Turn detection findings into a write decision.

        Kept separate from `poison.py` on purpose: detection is a fact about the
        content, the verdict is a policy about your environment. Merging them would
        hard-code one customer's risk appetite into the detector.
        """
        if report is None or report.empty or not self.poison_config.get("enabled", True):
            return PolicyDecision(True, "No poisoning signal", code="clean")

        severity = report.highest_severity or "low"
        action = str(self.poison_config.get(f"on_{severity}", "flag"))
        flags = tuple(f"poison:{kind}" for kind in report.kinds())

        if action == "reject":
            return PolicyDecision(
                False,
                f"Blocked by poisoning detection ({severity}) -- {report.reasons()}",
                flags=flags,
                code=f"poison_blocked:{severity}",
            )
        if action == "allow":
            return PolicyDecision(
                True, "Poisoning findings below the configured threshold", code="poison_ignored"
            )
        return PolicyDecision(
            True,
            f"Flagged by poisoning detection ({severity}) -- {report.reasons()}",
            flags=(*flags, f"poison_severity:{severity}"),
            code=f"poison_flagged:{severity}",
        )


def diff_configs(
    old: Mapping[str, Any], new: Mapping[str, Any], prefix: str = ""
) -> list[str]:
    """Human-readable list of what changed between two policy configs.

    Written generically so that adding a new policy key never silently stops being
    audited. A permission change that leaves no trace is the thing this whole
    project exists to prevent.
    """
    changes: list[str] = []
    for key in sorted(set(old) | set(new)):
        path = f"{prefix}{key}"
        if key not in old:
            changes.append(f"{path}: added ({_short(new[key])})")
        elif key not in new:
            changes.append(f"{path}: removed")
        else:
            before, after = old[key], new[key]
            if isinstance(before, Mapping) and isinstance(after, Mapping):
                changes.extend(diff_configs(before, after, prefix=f"{path}."))
            elif before != after:
                changes.append(f"{path}: {_short(before)} -> {_short(after)}")
    return changes


def _short(value: Any, limit: int = 60) -> str:
    text = repr(value) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out
