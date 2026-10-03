"""Concurrent-access check for a single store.

Why this exists separately from the test suite: the README claims WAL journalling, a
`busy_timeout`, and a connection lock, and every one of those claims is about *concurrent
access*. The unit tests cover threads inside one process. Nothing covered separate
processes -- which is how the CLI is actually used, and how an MCP server and an operator
CLI end up on the same file at the same time.

Run:

    python tools/concurrency_check.py --writers 8 --readers 4 --rounds 5

Exits non-zero on the first failed process or on a count mismatch, so it works as a
release gate. Failures print the offending process's output, because "3 of 8 failed" is
not an actionable message.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TENANT = "acme"


def _invoke(args: list[str]) -> list[str]:
    """Invoke the CLI through the interpreter rather than the console script.

    `python -m amnesia.cli` works in any environment where the package is importable,
    including a source checkout with no install and a venv the caller has not put on PATH.
    """
    return [sys.executable, "-m", "amnesia.cli", *args]


def _env(journal_mode: str) -> dict[str, str]:
    import os

    return {**os.environ, "AMNESIA_JOURNAL_MODE": journal_mode}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--writers", type=int, default=8, help="concurrent writer processes")
    parser.add_argument("--readers", type=int, default=4, help="concurrent reader processes")
    parser.add_argument("--rounds", type=int, default=5, help="writes per writer")
    parser.add_argument(
        "--journal-mode",
        default="auto",
        choices=["auto", "wal", "delete"],
        help="passed through as AMNESIA_JOURNAL_MODE; 'auto' allows the WAL fallback",
    )
    parser.add_argument("--keep", action="store_true", help="leave the store on disk")
    options = parser.parse_args()

    policy = REPO / "policies" / "default.yaml"
    expected = options.writers * options.rounds

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        store = Path(tmp) / "concurrent.db"
        audit = Path(tmp) / "concurrent.jsonl"
        base = [
            "--policy", str(policy),
            "--db", str(store),
            "--audit", str(audit),
            "--tenant", TENANT,
        ]
        print(f"store       {store}")
        print(f"journal     {options.journal_mode} (AMNESIA_JOURNAL_MODE)")
        print(f"writers     {options.writers} x {options.rounds} writes = {expected} expected")
        print(f"readers     {options.readers}")
        print()

        def write_round(worker: int, round_index: int) -> subprocess.CompletedProcess:
            return subprocess.run(
                _invoke(
                    [
                        *base,
                        "remember",
                        f"concurrent note {worker}-{round_index}",
                        "--source", "wiki",
                        "--scope", "project",
                    ]
                ),
                capture_output=True,
                text=True,
                env=_env(options.journal_mode),
            )

        def read(worker: int) -> subprocess.CompletedProcess:
            return subprocess.run(
                _invoke([*base, "recall", "concurrent note", "--principal", f"reader{worker}"]),
                capture_output=True,
                text=True,
                env=_env(options.journal_mode),
            )

        # All processes start from one barrier rather than being queued: the point is to
        # collide, and a thread pool alone would serialise the first few.
        tasks = [(write_round, (w, r)) for w in range(options.writers) for r in range(options.rounds)]
        tasks += [(read, (r,)) for r in range(options.readers)]

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(tasks)
        ) as pool:
            futures = {pool.submit(fn, *args): (fn, args) for fn, args in tasks}
            results = {key: future.result() for future, key in futures.items()}

        failures = [(key, result) for key, result in results.items() if result.returncode != 0]
        writes_failed = [key for key, _ in failures if key[0] is write_round]
        reads_failed = [key for key, _ in failures if key[0] is read]

        for (fn, args), result in failures[:3]:
            label = "write" if fn is write_round else "read"
            print(f"[FAIL] {label} {args} exited {result.returncode}")
            print((result.stdout + result.stderr).strip()[-600:])
            print()

        # And confirm the survivors agree about what is in the store.
        counted = subprocess.run(
            _invoke([*base, "--json", "stats"]),
            capture_output=True,
            text=True,
            env=_env(options.journal_mode),
        )
        total = None
        if counted.returncode == 0:
            import json

            try:
                total = json.loads(counted.stdout).get("total")
            except json.JSONDecodeError:
                total = None

        print(f"writes failed  {len(writes_failed)}")
        print(f"reads failed   {len(reads_failed)}")
        print(f"memories       {total} (expected {expected})")

        problems = []
        if writes_failed:
            problems.append(f"{len(writes_failed)} writer(s) exited non-zero")
        if reads_failed:
            problems.append(f"{len(reads_failed)} reader(s) exited non-zero")
        if total != expected:
            problems.append(f"store holds {total}, expected {expected}")

        if problems:
            print()
            for problem in problems:
                print(f"FAIL  {problem}")
            if options.keep:
                print(f"store kept at {store}")
                return 1
            return 1

        print()
        print("Concurrent access clean: no failed processes, no lost writes.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
