# Changelog

Notable changes per release. The project follows [Semantic Versioning](https://semver.org/),
and policies are versioned separately through the `revision` key in the policy file.

## [0.2.0] — 2026-09-29

The release that turns the working proof into something deployable.

### Added

- **The audit log is hash-chained.** Every entry now carries a `seq`, the previous entry's digest
  and its own, so modifying an entry, deleting one (a sequence gap) or reordering two are all
  detected, and `amnesia verify` names the first entry that fails and why. Until now "a
  tamper-evident trail" was a docstring: the log was append-only, which prevents an accidental
  rewrite and proves nothing about an intentional one.

  Appends take an exclusive lock (`msvcrt` / `fcntl`), and that is load-bearing rather than
  defensive — chaining needs the previous digest, so an append is a read-modify-write, and
  without the lock two processes build on the same predecessor and the log becomes
  **indistinguishable from tampering**. Verified with 40 concurrent writes from separate
  processes: 40 entries, chain intact.

  Three states, deliberately not two: `intact` (every chained entry verified), `partial` (the
  chained region verified, but some entries predate chaining or a line could not be parsed), and
  `broken` (a chained entry failed). `partial` is a warning in `verify` — a log that cannot be
  fully verified is not the same as one that was altered, and reporting it as healthy would
  overstate the evidence. **Truncation is not detectable**, and `SECURITY.md` says so: a chain
  with no external anchor cannot prove that more once existed.
- **`mypy` and coverage are gates.** `mypy` is clean across all 17 modules and coverage is 93%,
  with a floor of 90% in `pyproject.toml` so a real drop fails rather than going unnoticed.
  Switching the type checker on found two genuine defects: a `raise` mypy could not prove
  non-`None`, and a predicate annotated narrower than the errors it is actually handed.
- **`tools/acceptance.py`** — ten waves of checks in one command: static integrity, test
  isolation, the CLI contract, the MCP surface, multi-process concurrency, the full permission
  matrix, the security probes, durability, boundary inputs, and an end-to-end day that
  reconciles the compliance report against the audit stream. Exit code 0 only when every wave
  passes, so it works as a release gate, and `--wave N` runs one. Deliberately separate from the
  test suite: "is each unit correct" and "will this work for someone" are different questions,
  and every defect those waves encode was found by running the product rather than its tests.
- `.gitattributes` normalising line endings, so a Windows contributor does not produce a diff
  that touches every line of every file.
- `CHANGELOG.md` records what was wrong and how it was found, including the wrong turns.

- **Poisoning detection** (`poison.py`). The write gate judges one memory at a time;
  poisoning is a pattern. Four detectors: injected instructions stored as "facts",
  fact flipping by an untrusted source, untrusted provenance into protected scopes, and
  bursts of writes against one subject. Severity-to-action mapping is policy
  (`on_high` / `on_medium` / `on_low`), because risk appetite is an environment
  property, not a content property.
- **Write-attempt ledger.** Every attempt, including rejected ones. A store of
  successes cannot show a burst of *refusals*, which is the signature of probing.
- **BM25 retrieval** replacing overlap scoring, with an inverted index in SQLite.
  Naive overlap has no notion of term rarity, so a match on "policy" counted as much
  as a match on a rare identifier. No external service, no second index to sync.
- **Policy versioning, hot reload and change auditing.** The policy file is
  fingerprinted; changes are picked up on the next request and audited with both
  fingerprints plus a human-readable diff. A broken edit keeps the last known good
  policy in force and is reported once rather than on every request.
- **`MemoryBackend` protocol** (`backend.py`), making "sits in front of the store you
  already run" a tested extension point rather than a claim. `WriteAttemptLedger` is a
  separate, optional protocol; absent it, the governor falls back to an in-process
  ledger and records the degradation.
- **Compliance report** (`report.py`) and an operator CLI (`amnesia`): `remember`,
  `recall`, `stats`, `verify`, `flagged`, `report`, `explain`, `sweep`, `audit`, `policy`.
  `remember` and `recall` exist so the core behaviour can be exercised from a shell —
  without them, trying Amnesia meant running the demo or writing Python, which is a poor
  first experience for a layer meant to sit in front of another system.
- **Deployment diagnostics** (`diagnostics.py`), shared by the CLI and the MCP surface.
- **Input validation** (`validation.py`). Rejected rather than coerced: a truncated
  document or a dropped role would make the audit record describe something that did
  not happen.
- Machine-readable rule codes on every decision, so reports never parse prose.
- **Every audit entry is stamped with the policy revision in force when it was written.**
  Without it, a historical decision cannot be tied to the permissions that permitted it,
  and the report flags windows in which permissions changed.
- Four new MCP tools: `memory_flagged`, `memory_report`, `memory_verify`, `memory_policy`.
- `tools/mcp_smoke.py`: an end-to-end stdio transport check, usable as a release gate.
- `SECURITY.md` (threat model, what counts as a vulnerability, explicit non-goals) and
  `CONTRIBUTING.md` (the conventions that actually get enforced in review).
- A ruff rule set, verified clean against this codebase before being written down, wired
  into CI as a lint gate.
- `amnesia --version`.

### Changed

- **Breaking:** denial records now include a `rule` code. Consumers reading the fixed
  key set will need to allow for it.
- **Breaking:** `MemoryStore` constructor takes `durability` and `busy_timeout_ms`;
  writes default to `synchronous=FULL` rather than SQLite's `NORMAL`, because this file
  holds deletion evidence.
- `forget` on a request that matches nothing now reports `deleted: False` with reason
  `No memories matched the request`. Reporting success for a no-op would put a false
  statement in a compliance file.
- The built-in default policy now matches the shipped `policies/default.yaml`. When the
  two disagreed, the same permission question got different answers depending only on
  how the engine was constructed.
- SQLite schema version 2: adds `doc_len` on `memories`, the `terms` index and the
  `write_attempts` ledger. Existing databases are upgraded in place, with the term
  index rebuilt automatically.

### Fixed

- **One damaged audit line made the entire trail unreadable.** `entries()` called `json.loads`
  on every line and raised on anything it could not parse, so a writer killed mid-append — which
  leaves a half-written line, and is a normal thing to find in a file customers grep and archive
  — took down `report`, `verify`, `explain` and `flagged` at once. Damaged lines are now skipped
  and **counted** (`unreadable_lines`), the count appears in the chain summary, and `audit --tail`
  — the command an operator reaches for *while* something is wrong — no longer refuses to run.
- **Redaction was quadratic, so a large write blocked a worker for almost a minute.** The email
  pattern had no boundary anchor while every other pattern did, so `[A-Za-z0-9._%+\-]+` swallowed
  a whole run of ordinary characters, failed to find `@`, and backtracked one character at a time
  from *every* start position inside the run — O(n²). Measured with plain text:

  | content | before | after |
  | --- | --- | --- |
  | 1 KB | 1 ms | 0.1 ms |
  | 20 KB | 278 ms | 2.2 ms |
  | 100 KB | 7.4 s | 12 ms |
  | 256 KB | **49.7 s** | **31 ms** |

  `MAX_CONTENT_BYTES` permits 256 KB, so a single permitted write pinned a worker for 49 seconds
  — long enough to trip any MCP client's timeout. Redaction is on the critical path of every
  write, and the fix is the anchor the other four patterns already had. Semantics are unchanged:
  real addresses are redacted, `USER@@example.com` and `bare@domain` still are not, and ISO dates
  and amounts are still left alone.
- **One malformed audit timestamp destroyed the compliance report.** `parse_iso` promised
  `datetime | None` but raised on an unparseable value, and a single hand-edited or half-written
  line took the whole report down — the artifact you hand to an auditor, refused over one bad
  line. The audit log is deliberately a plain JSONL file that customers grep, diff and archive,
  so that line is a normal thing to find. Unreadable entries are now excluded from every count
  **and counted**, with a note in the report saying so; dropping them silently would hide the
  case most worth reviewing.
- **An explicitly empty `--scope` silently became the default scope.** `normalize_scope` was
  `scope or default`, so `""` — an unset shell variable, an empty form field, an MCP argument
  dropped in transit — was promoted to `project` and placed a memory the caller meant to restrict
  where everyone could read it. `None` still means "use the default"; an empty string is now a
  validation error. This was fail-open, and the test that should have caught it asserted the
  fail-open behaviour instead.
- **An `--audit` path pointing at a directory raised a bare `PermissionError`**, on the first
  append, from inside pathlib. That is not an `AmnesiaError`, so the CLI did not catch it and the
  operator got a traceback for a mistyped path. Checked at construction, reported as
  `Cannot open audit log at '...': it exists but is not a file.`
- **A transient file-access error failed a governed write outright.** On Windows a file another
  handle has open reads as "permission denied", and it is frequently transient — antivirus, the
  search indexer, a process deleting SQLite's journal file. It arrives as a bare
  `PermissionError`, **not** as a `sqlite3.Error`, so retry logic that only caught the sqlite3
  type let the write fail. Found by a concurrency test that failed reproducibly inside a full
  test run while passing on its own: the host refused exactly one journal-file deletion.

  `_read` and `_write` now also retry `OSError` with errno 5, 13 or 32 (access denied and
  sharing violation), bounded and with backoff, then raise. EPERM and ENOSPC are deliberately
  *not* retried — they do not clear if you wait, so retrying would only delay the error.
- **Every write committed twice.** The memory row and its write-attempt record went in separate
  transactions. On a filesystem where a commit costs a flat ~28ms, that halved throughput to
  **17 writes/second**; combining them reaches **31–33** — measured at 1.8–1.9× by running both
  paths back to back in one process. (An earlier standalone measurement suggested 381/s, which
  was environmental: absolute commit cost on this filesystem varies by an order of magnitude, so
  only comparisons within one run are trustworthy.) Atomicity is the better half of the argument
  anyway — with two transactions a crash between them leaves a memory the ledger has no record
  of, and the ledger is what burst detection counts. A backend that does not offer the combined
  insert falls back to two transactions.
- **A read-gate bypass in `memory_explain`.** The tool took only a memory id and returned the
  content, so an agent correctly refused by `memory_recall` could read the same memory through
  the explanation endpoint if it knew the id — twelve characters that appear in logs and in
  other tool output. An explanation endpoint more permissive than the thing it explains is not
  an explanation endpoint.

  `explain` now takes an optional principal that gates the content through the same read gate
  as a recall, and withholds it when no principal is supplied — the same reasoning already
  applied to `memory_flagged`, and the rule this project had written down in `CONTRIBUTING.md`
  while violating it. The CLI gained `--principal`; asking to see content is a read, so it is
  audited as one (`memory.explain`).
- **Poisoning audit records carried a snippet of the content they refused.** The verdict's
  reason embeds the matched text, and the audit log is built to be greppable and archivable —
  so it is readable by people and systems that cannot read the store. Findings are now recorded
  as severity and kinds only (`PoisonReport.audit_summary()`); the full detail still goes to the
  caller, who already had the content.
- **The CLI printed Python tracebacks for user error.** A misspelled `--scope`, an out-of-range
  confidence, an empty content argument — all reached the operator as a stack trace, which reads
  as a broken tool. They now exit **2** with `error: <message>` on stderr, matching what
  argparse already did for bad flags. The contract is now 0 worked / 1 the gate refused you /
  2 you called it wrongly, so a script can tell a policy decision from a typo without parsing
  prose.
- **A mistyped `--policy` path raised a bare `FileNotFoundError`** from inside pathlib instead
  of naming the file that was missing.
- **An unrecognised role was silently treated as clearance 0.** Safe, but a typo like
  `--roles empolyee` presented as "the policy denies me", which sends an operator to debug the
  policy. Unknown roles are now reported in the recall result, in the audit record, and as a
  warning from the CLI.
- **Concurrent processes lost writes.** Ten concurrent `amnesia remember` invocations against
  one store lost 23 of 50 memories, each failure a raw `sqlite3.OperationalError: attempt to
  write a readonly database`. Amnesia's own claims — WAL, `busy_timeout`, a connection lock —
  are all claims about concurrent access, and nothing had ever tested concurrency across
  *processes*, which is how the CLI is actually used.

  Four separate causes, found in this order:

  1. `busy_timeout` was set *after* `PRAGMA journal_mode`. A timeout configured after the
     contentious operation is not a timeout.
  2. Every connection re-issued `PRAGMA journal_mode=WAL`, though WAL is a persistent property
     of the file. While one process transitions the journal mode it holds an exclusive lock,
     and every other process — including ones already open and mid-transaction — gets
     `SQLITE_READONLY`.
  3. Retries existed for neither reads nor writes, and `busy_timeout` does not cover a
     journal-mode transition or the window in which another process creates the `-wal` and
     `-shm` files.
  4. The fallback that steps down from WAL to the rollback journal was held in memory. Every
     CLI invocation is a fresh process, so it was forgotten immediately: the next process
     re-enabled WAL, hit the same failure, and the store never converged — visible as a
     failure count that oscillated instead of settling. It is now recorded in `store_meta`
     inside the database, and the connection is replaced before retrying.

  **This was not entirely Amnesia's bug, and the diagnosis matters.** A control experiment of
  30 concurrent writer processes running plain `sqlite3` — no Amnesia code at all — showed WAL
  failing up to 9/30 in a project directory and 5/30 in the system temp directory, while the
  rollback journal succeeded 30/30 in both. WAL needs a shared-memory file that some
  filesystems will not sustain. But a governed write may not be lost to a filesystem property,
  so the store now adapts and says so.

  With the fixes: 10 writers × 5 rounds plus 4 readers, clean across 6 consecutive trials.
  `tools/concurrency_check.py` is now a release gate, and `journal_mode` is configurable
  (`auto` / `wal` / `delete`) through `AMNESIA_JOURNAL_MODE`.

  **That conclusion was incomplete, and the way it was incomplete is worth recording.** Those
  six clean trials were on an idle machine. Re-running the same command on a loaded one failed
  6 of 8 trials — the failure rate is load-dependent, so a clean run says nothing unless it was
  measured under load. Two further attempts (react immediately on `SQLITE_READONLY` rather than
  exhausting the retry budget; persist the fallback decision in the database) each looked
  correct and each still failed 6 of 8 trials under load, because **the step-down is itself a
  contended operation** — the journal-mode switch wants an exclusive lock, and the worst moment
  to need one is the first burst against a fresh store, before any process has recorded the
  decision.

  The resolution was to stop managing the failure and remove it: **`auto` no longer switches
  *into* WAL.** It keeps whatever the file already uses. WAL is opt-in via
  `journal_mode="wal"` / `AMNESIA_JOURNAL_MODE=wal`, for stores on a filesystem that supports
  shared memory. WAL is a concurrency improvement, not a correctness one, and on the wrong
  filesystem it is a correctness regression — so the safe mode is now the default and the fast
  mode is a deliberate choice. Measured after the change: **10 of 10 trials clean under load.**
- **`recall` did not show the `subject`.** Two memories about different subjects read as
  near-identical lines; the subject is what explains why a memory exists and what a later
  write would supersede.
- **`sweep`'s supersede list wrapped in a normal-width terminal** and read as a ragged
  column. Shortened — the heading above it already says what happened.
- **`deny_roles` was a veto on the principal instead of an exclusion of a role.** It was
  any-match while clearance was a max over roles — two rules pointing in opposite directions
  — so somebody who was both an employee and HR was refused HR records *because* of the
  employee role. Holding two roles left them less able to read than holding one, and an
  admin who also did contract work lost admin reach. Effective clearance is now computed
  from the roles that are not barred.
- **`amnesia forget` did not exist.** Physical deletion and its receipt are the parts of this
  product a reviewer asks to see, and they were reachable only through MCP or Python. Now on
  the CLI, with exit 0 on deletion and 1 on refusal, and a refusal path that never prints the
  content it refused.
- **`remember` printed a poisoning refusal twice.** The verdict's reason already embeds every
  finding, so the CLI led with the long sentence and then listed the same findings again.
- **`stats`, `sweep`, `policy`, `explain` and `audit` printed Python dict reprs.** The other
  commands had human output, but these five dumped `repr()` at the operator. Worst of all
  for `explain`, which exists to make the audit trail legible to someone who is not going to
  write Python to read it — it now tells the whole story of a memory: when it was written,
  how often it was refused and to whom, whether a later write was recognised as a duplicate,
  and whether it was superseded. `--json` is still there for scripts, and a test asserts the
  human output never contains a bare `{`.
- **The MCP server's lazy governor had no lock.** Concurrent tool calls each found
  `_governor is None` and built their own: eight concurrent callers produced eight
  governors — eight SQLite connections to one file, eight handles appending to one audit
  log, eight WAL setup passes racing. Under repeated runs it surfaced as an intermittent
  `Error executing tool memory_recall`, which is the worst kind of defect for a governance
  layer: rare, load-dependent, and invisible until it is not. Now double-checked locking,
  with a test that asserts exactly one governor is built from eight threads.
- **`tools/mcp_smoke.py` fired `memory_write` and `memory_recall` back to back**, so the
  server dispatched them concurrently and the recall could race the write it depends on —
  the check then failed with "returned 0, withheld 0" for a reason that had nothing to do
  with the server. It now awaits each reply before issuing the next call, which is what a
  real client does. Verified 15/15 consecutive passes.
- **Writes are now idempotent** when content, source and `subject` all match: the existing
  memory is returned with `duplicate: true` instead of a second row being created. Without
  it, re-running an ingest duplicated the fact and recall returned it twice, which to an
  agent is not merely wasted context — it looks like a broken system. Requires a `subject`
  (the caller declaring what the memory is about) and a matching source (a second source is
  corroboration, not a duplicate). Checked before poisoning detection so a retry storm is
  not flagged as an attack. `memory.write_duplicate` events, `writes_duplicate` in the
  headline, `write.duplicates` in the JSON.
- **The report's "stored writes, by what the gate did to them" table mixed in poisoning
  codes.** Records written before the write gate emitted codes carry the poisoning verdict
  in `rule`, so the table rendered "no poisoning signal" under a heading about the write
  gate. It is now derived from `flags`, which have been recorded since the beginning and are
  therefore correct for every record ever written.
- **The write gate recorded no rule codes at all.** The read gate and the poisoning verdict
  had them; the entire write path did not, so every rejected write rendered in the
  compliance report as `unspecified` — which a reviewer cannot act on. "We refused 40
  writes" is not reviewable; "40 writes, all containing credentials" is. All six
  `evaluate_write` branches now carry a code, the report labels them, and it gained a
  "stored writes, by what the gate did to them" breakdown so redactions are visible
  (`writes_redacted` in the headline, `write.stored_breakdown` in the JSON).
- **`rule` on a stored write held the poisoning verdict's code**, not the write gate's, so
  stored writes could not be grouped by outcome. The verdict now lives in its own
  `poison_code` field.
- A record with no code is now labelled "no rule code recorded" rather than sharing a word
  with codes the report does not recognise — historical entries predate codes and the log
  is append-only, so they cannot be rewritten.
- **The CLI and the MCP server resolved the default policy differently.** The server
  fell back to the shipped policy file; the CLI fell back to the built-in defaults. One
  product, two permission models, and nothing to tell you which one you were running. Both
  now go through `policy.resolve_policy_path` (explicit → `$AMNESIA_POLICY` → shipped).
- **The policy did not ship inside the package**, so a real (non-editable) install had no
  policy file and silently degraded to the built-in defaults. It is now package data, and a
  test asserts the packaged copy and the editable copy at the repo root stay byte-identical.
- **The report announced "Permissions changed during this window" when nothing had.**
  Passing `--policy` on some commands and not others produced two apparent revisions. It now
  distinguishes three states: a real permission change, a window with no policy file mounted
  at all, and a mix of the two — each with its own wording, because the operator's fix
  differs. `policy_changed_mid_window`, `policy_without_a_file` and `policy_config_mixed`
  are exposed as machine-readable fields.
- `post_filter` could return fewer results than `pre_filter`, for the same query and
  identity.** A single truncated candidate window let refused memories crowd out memories
  the caller was cleared for; with twelve refused memories and one authorised memory, the
  authorised one was simply not returned. The scan now walks candidates in pages. Bounded
  by `MAX_CANDIDATE_PAGES`, and a query dense enough to exhaust it records a
  `governance.degraded` event rather than failing quietly.
- **Memories without a `subject` never decayed.** Time decay skipped them, so they
  accumulated forever, kept influencing recall, and never appeared in a retention report.
- **`refusal_rate` was meaningless** — it divided refusals by recall count times five.
  Refusals are now measured against `candidates_evaluated`, which the read audit records.
- **BM25 corpus statistics were read under two separate lock acquisitions**, so a
  concurrent write could land in between and the document frequencies would describe a
  different corpus than the document count.
- **`AuditLog.tail` read the entire log** to return twenty lines, which is precisely wrong
  when the log has grown large.
- Deliveries to a protected scope are no longer reported as successful deletions.
- Deletion refusals record the refusal explanation, not just the caller's stated reason.
- The demo crashed if its output directory contained a subdirectory: it globbed and
  unlinked everything rather than removing only the files it owns.

### Tests

238 tests, covering governance, retrieval ranking and paging, poisoning, write idempotency,
policy reload and resolution, the backend seam, validation, durability (including the journal
mode default and the fallback), migration, concurrency, the report, the CLI and the MCP
surface. `tools/mcp_smoke.py` exercises the stdio transport end to end and
`tools/concurrency_check.py` exercises multi-process access under load.

## [0.1.0] — 2026-09-29

First working version.

- Write gate: credential rejection, PII redaction at write time, mandatory provenance.
- Read gate: identity-scoped recall with two retrieval paths (`pre_filter` and
  `post_filter`) that must agree, and refusal records that never carry content.
- Forgetting engine: time decay, fact supersession with a preserved version chain, and
  physical deletion with a hash-bearing compliance receipt.
- Append-only JSONL audit stream.
- MCP server with seven tools.
- 22 tests.
