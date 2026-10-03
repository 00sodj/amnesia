# Contributing

Small project, strong opinions. Read this before sending a patch — it will save us both a
review cycle.

## Getting set up

```bash
pip install -e ".[dev,server]"

ruff check .                 # lint — zero findings is the baseline
pytest                       # the whole suite
python demo/demo_run.py      # the walkthrough, writes to .demo/
python tools/mcp_smoke.py    # stdio transport + tool registration
```

The project targets Python 3.10+ and keeps exactly one runtime dependency (`PyYAML`).
Adding a second needs a justification in the pull request; "it made this line shorter" is
not one.

The ruff rule set in `pyproject.toml` was verified clean against this codebase before
being written down. Keep it that way: if you add a rule, fix its findings in the same
change. If a finding is a genuine false positive, suppress it inline with a comment
saying why — as `tests/test_poison.py` does for its deliberately CJK payload.

## The rules that actually matter

**Every claim in the README has a test.** The README is the product's specification, and
it is long, so it is easy to write a sentence that sounds right and is not. If you change
a documented behaviour, change its test in the same commit. If you delete a promise,
delete its test with it. If you state a number — test counts, limits, defaults — check it
rather than recalling it.

**No dead code, including in `tools/`.** A half-used helper or an unused parameter is what
makes a project read as unfinished. If you remove the last caller, remove the code.

**Comments explain *why*, not *what*.** The code already says what it does. What the next
reader cannot recover is the reasoning: why this order, why not the obvious approach, what
breaks otherwise. The existing modules set the density; match it.

**Failures are named, never silent.** Errors use the hierarchy in `errors.py`. If a
guarantee is being weakened — a missing ledger, a stale index, a scan that gave up — the
choice is either to raise, or to record a `governance.degraded` event. Quietly returning a
degraded answer is the one option that is not available.

**Validate before side effects.** A rejected call must leave no memory, no write attempt
and no audit entry. Anything else means the audit trail describes something that did not
happen.

## Testing notes

- Tests are grouped by concern: `test_governance`, `test_retrieval`, `test_poison`,
  `test_policy_reload`, `test_backend`, `test_durability`, `test_report_cli`,
  `test_diagnostics_and_server`.
- A bug fix needs a test that fails before the fix. Say in the test's docstring what the
  wrong behaviour was, so a future reader can tell whether the test still earns its place.
- Shared test doubles live in `tests/_helpers.py`.
- Concurrency is tested, not assumed. If you touch the store, keep the locking honest and
  run the threaded tests.

## Changing the security model

Anything that touches authorisation needs more than a passing test. Specifically:

- If you change `policy.evaluate_read` ordering, explain why in the docstring. The order
  determines which reason a user sees and which rule wins when two apply.
- If you add a code path that bypasses a gate, that is a finding, not a feature. Open an
  issue first.
- If you add content to an audit record, check it against the module docstring rule:
  refusals carry id, scope, rule and reason, and never content.
- If you touch the MCP surface, remember it has no caller identity. A tool that returns
  content there is a read-gate bypass unless it takes and validates a principal.

## Commits and pull requests

Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`), one
logical change per commit. In the pull request, state what was wrong before and how you
know it is right now — a command you ran and its output beats a description.

## Reporting a vulnerability

Not through a pull request or a public issue. See [SECURITY.md](SECURITY.md).

## Publishing this repository

Not done for you — the maintainer decides when this goes public. When it is time:

```bash
cd amnesia
git init -b main
git add -A
git commit -m "feat: initial public release"

# The repository name must not be taken; `amnesia` on PyPI is somebody else's package,
# so pick a distribution name you own before publishing there.
gh repo create <your-account>/amnesia --public --source=. --remote=origin --push
```

Before the first push, check these, because a public repository is much harder to edit than
working tree:

- **Run `python tools/acceptance.py` and paste the output into the release notes.** Ten waves
  green is a stronger claim than a feature list.
- **`.gitignore` must be doing its job.** `git status --short` should show no `*.db`,
  `*.jsonl`, `.demo/`, or `__pycache__`. The `.demo/` and `try*.db` entries exist because
  running the demo and the CLI by hand produces stores that must never be committed — an audit
  log is evidence, and someone else's audit log in a public repository is a leak.
- **Search the tree for real names and real data** before publishing. The sample data is
  deliberately fictional (Dana Whitfield, Northwind, Acme) but a careless copy-paste from a
  real incident is easy to miss: `grep -rniE "your-employer|real-name|@yourcompany" .`
- **`CHANGELOG.md` is the story of the project.** It records what was wrong and how it was
  found, including the mistakes — keep that tone. A release note that only lists features tells
  a reader nothing about whether to trust the code.
- **Decide the licence before the first push.** `LICENSE` is MIT; changing it after others have
  depended on it is not a thing you can do unilaterally.
