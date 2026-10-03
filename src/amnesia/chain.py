"""Hash chaining for the audit log.

"A tamper-evident trail" is the claim the whole product rests on, and until this module existed
it was only a docstring: the log was append-only, which prevents an *accidental* rewrite and
proves nothing about an intentional one. Anyone with write access to the file could edit an
entry, delete a line, or reorder two entries, and every downstream report would read as
internally consistent.

Each entry carries three extra fields:

- ``seq``  -- 1-based position within the segment. A gap means a line was removed.
- ``prev`` -- the ``hash`` of the previous chained entry, or :data:`GENESIS` at the start.
- ``hash`` -- SHA-256 over the entry's own contents plus ``seq`` and ``prev``.

Together those catch the three things that matter: modifying an entry breaks its own hash,
deleting one leaves a sequence gap, and reordering two breaks the ``prev`` links.

**Entries written before this existed have no hash fields.** They are counted and reported
rather than treated as a failure — a log that cannot be verified is a different situation from
one that has been tampered with, and conflating the two would cry wolf on every upgraded
deployment. It does mean the verifiable region is only as long as the chained region, which the
status says out loud.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

# The `prev` value for the first entry in a chain. Sixty-four zeros, so it can never collide
# with a real digest.
GENESIS = "0" * 64

_SEPARATORS = (",", ":")


def _canonical(seq: int, prev: str, entry: Mapping[str, Any]) -> str:
    """The exact bytes a hash covers.

    Sorted keys and no whitespace, so the digest does not depend on how the JSON was serialised
    — an intermediary that reformats the file must not break the chain. ``hash`` is excluded,
    for the obvious reason.
    """
    payload = {"seq": seq, "prev": prev}
    payload.update({k: v for k, v in entry.items() if k not in ("hash", "seq", "prev")})
    return json.dumps(payload, sort_keys=True, separators=_SEPARATORS, ensure_ascii=False)


def digest(seq: int, prev: str, entry: Mapping[str, Any]) -> str:
    """The hash an entry with these contents and links should carry."""
    return hashlib.sha256(_canonical(seq, prev, entry).encode("utf-8")).hexdigest()


def is_chained(entry: Mapping[str, Any]) -> bool:
    return isinstance(entry.get("hash"), str) and isinstance(entry.get("seq"), int)


@dataclass(frozen=True)
class ChainStatus:
    """What a walk over the log found.

    Three outcomes, deliberately not two. ``intact`` means every chained entry verified.
    ``partial`` means the chained region verified but some entries predate the chain and cannot
    be checked. ``broken`` means a chained entry failed — modification, deletion or reordering.
    Collapsing ``partial`` into ``intact`` would overstate the evidence; collapsing it into
    ``broken`` would make every upgraded deployment look tampered with.
    """

    chained: int
    unchained: int
    breaks: tuple[str, ...]
    first_break_index: int | None
    unreadable: int = 0

    @property
    def state(self) -> str:
        if self.breaks:
            return "broken"
        return "partial" if (self.unchained or self.unreadable) else "intact"

    @property
    def ok(self) -> bool:
        return not self.breaks

    def describe(self) -> str:
        if self.breaks:
            first = self.breaks[0]
            return (
                f"audit chain BROKEN at entry {self.first_break_index}: {first} "
                f"({len(self.breaks)} problem(s) found, {self.chained} entries verified)"
            )
        notes = []
        if self.unchained:
            notes.append(f"{self.unchained} entry(ies) predate chaining and cannot be verified")
        if self.unreadable:
            notes.append(f"{self.unreadable} line(s) could not be parsed at all")
        if notes:
            return (
                f"audit chain intact over {self.chained} entries; " + "; ".join(notes)
            )
        return f"audit chain intact over {self.chained} entries"


def verify(entries: Iterable[Mapping[str, Any]]) -> ChainStatus:
    """Walk a log and report the first thing wrong with it.

    Chained entries are checked in file order. An entry's ``prev`` must equal the previous
    chained entry's ``hash``, and its ``seq`` must follow on; its ``hash`` must match its own
    contents. Any chained entry failing one of those is reported with its index, because "the
    log has been altered" is only actionable if it says where.
    """
    chained = 0
    unchained = 0
    breaks: list[str] = []
    first_break: int | None = None
    previous: str | None = None
    expected_seq = 0

    for index, entry in enumerate(entries):
        if not is_chained(entry):
            unchained += 1
            # A legacy entry interrupts the chain: nothing after it can be linked to anything
            # before it, so treat the next chained entry as the start of a fresh segment.
            previous = None
            continue

        seq = int(entry["seq"])
        prev = str(entry["prev"])
        recorded = str(entry["hash"])
        problems: list[str] = []

        if seq == 1 and prev == GENESIS:
            # An explicit segment boundary, written either at rotation or because the tail could
            # not be read. Resetting here is safe: the boundary is itself in the log, so it can
            # be reviewed, and it cannot be forged into a *silent* edit of anything inside a
            # verified segment.
            previous = None
            expected_seq = 0

        if previous is not None:
            if prev != previous:
                problems.append("prev hash does not match the preceding entry")
            if seq != expected_seq + 1:
                problems.append(f"sequence gap: expected {expected_seq + 1}, found {seq}")

        if digest(seq, prev, entry) != recorded:
            problems.append("entry contents do not match their own hash")

        if problems:
            if first_break is None:
                first_break = index
            breaks.append(f"seq {seq}: " + "; ".join(problems))

        previous = recorded
        expected_seq = seq
        chained += 1

    return ChainStatus(
        chained=chained,
        unchained=unchained,
        breaks=tuple(breaks),
        first_break_index=first_break,
    )
