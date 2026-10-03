# Security policy

Amnesia is a security control. A defect here can mean an agent discloses something it
should not, or fails to forget something it was required to forget. Reports are taken
seriously and are the most useful contribution you can make to this project.

## Reporting a vulnerability

**Do not open a public issue for a security defect.** Open a private security advisory on
the repository (GitHub: *Security* → *Report a vulnerability*). If you cannot, contact a
maintainer directly and say only that you have a security report, without details.

Please include:

- the affected version (`amnesia --version`, or the commit hash)
- a minimal reproduction: the policy in force, the memories written, the identity asking,
  and what came back
- the impact as you understand it, and whether you exploited it or only inferred it

You will get an acknowledgement within a few days. This is a small project, so please
allow reasonable time before disclosing publicly.

## What counts as a security defect

Anything that breaks one of the guarantees the README makes:

| Guarantee | A defect looks like |
| --- | --- |
| Read gate | A principal receives a memory its roles do not clear it for |
| Read gate | The two retrieval paths disagree about authorisation |
| Read gate | Refusal records leak content into the audit log |
| Write gate | A credential is stored, or personal data is stored unredacted |
| Write gate | Validation is bypassed by type coercion or unexpected input |
| Poisoning detection | An injected instruction is stored as a normal memory |
| Poisoning detection | An untrusted source supersedes a trusted fact |
| Forgetting | A deletion reports success without physically removing the row |
| Forgetting | Superseded content is still returned by recall |
| Audit | A decision is not recorded, or is recorded without the policy revision |
| Audit | An audit entry can be edited or removed through the API |

## Explicit non-goals

These are known limits, documented in the README, and are not vulnerabilities:

- **The audit log is hash-chained, but the chain has no external anchor.** Every entry carries a
  `seq`, the `prev` entry's digest, and its own digest, so **modifying** an entry, **deleting**
  one (a sequence gap) and **reordering** two are all detected, and `amnesia verify` names the
  first entry that fails. What it cannot detect is **truncation**: lopping off the tail leaves a
  self-consistent prefix, and nothing inside the file can prove that more once existed. Closing
  that needs an anchor the log's owner does not control — publish the head digest somewhere else,
  or countersign periodic segments. Signing is on the roadmap; if your threat model includes an
  operator with disk access who can also destroy evidence, this is not yet the control for that.
- **A log rotated or truncated at the filesystem level starts a new chain segment**, which is
  visible in the file (a `seq 1` / genesis `prev`) but is not itself authenticated. Treat the
  presence of an unexpected segment boundary as something to investigate.
- **Policy trust is declared, not enforced.** `trusted_sources` is a list you maintain.
  Amnesia does not authenticate the caller's claimed `source`.
- **Identity is asserted by the caller.** `Principal` is a data structure you construct.
  Amnesia does not authenticate it; that belongs to whatever sits in front of it. Passing
  an attacker-controlled role list defeats every permission check, by design.
- **No rate limiting.** Burst detection raises findings; it does not throttle.
- **Single-node.** The store is one SQLite file; it is not a distributed system.

## Hardening checklist for operators

Run `amnesia verify` before trusting a deployment, and check that:

- `source trust declared` is **ok**, not a warning — an empty `trusted_sources` means the
  fact-flip and provenance detectors cannot fire at all
- `protected scopes declared` is **ok** for the same reason
- `term index fresh` is **ok** — a stale index silently degrades recall
- the policy file is version-controlled and its changes are reviewed as permission diffs
- `AMNESIA_DB` and `AMNESIA_AUDIT` are on storage you back up, since the audit log is your
  evidence
- `AMNESIA_POLICY_ACTOR` is set, so policy changes are attributable in the audit stream
