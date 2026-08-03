# REVIEW-ACL-011 Public Release Hygiene Design

**Status:** implemented in `af6accb`. Exact implementation-head Build
[`30811728869`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30811728869)
passed every required hosted lane. Current tracked paths/content and future
payloads are covered; historical Git objects were deliberately not rewritten.

## Problem

The source repository is already public. The current tree therefore exposes
more than the binary and Kolla release payloads: maintained documentation,
package metadata, examples, tests, generated presentations, and committed field
evidence are also public surfaces.

The existing repository and payload policy blocks an earlier set of prohibited
terms, but it has four gaps for `REVIEW-ACL-011`:

1. it does not cover the agreed personal, workstation, target-host, and target
   network identifiers;
2. the repository checker scans file content but not tracked path names;
3. archived tracked output needs archive-member-aware inspection rather than a
   raw compressed-byte search;
4. public documents and fixtures still repeat environment-specific values even
   though the corresponding examples can use standards-reserved placeholders.

Removing strings only from future binary archives would not close the issue,
because the repository itself is public. Rewriting Git history would address a
different and destructive problem: it would invalidate commit identities,
hosted CI URLs, existing clones, and evidence references. That operation is not
authorized by this batch.

## Decision

Perform deterministic anonymization of the complete current tracked tree and
all future release payloads. Preserve the semantic relationships and results of
field evidence. Do not rewrite Git history.

The implementation has three parts:

- replace in-scope identifiers in current tracked path names and textual or
  archive content;
- strengthen the existing repository and payload policy so those identifiers
  cannot return;
- document the exact boundary: current HEAD and future artifacts are clean,
  while historical commits remain unchanged.

## Alternatives considered

### 1. Scan only binary and Kolla release payloads

This is too narrow because source, documentation, fixtures, evidence, and
generated presentations are directly visible in the public repository.

### 2. Deterministic current-tree anonymization — selected

This removes identifiers from the live public surface, keeps evidence
cross-references usable, and establishes a regression gate without disrupting
Git history.

### 3. Rewrite all Git history

This could remove old values from historical objects, but requires coordinated
force pushes and invalidates existing commit, CI, and evidence links. It must be
a separately authorized repository-migration task if ever required.

## Identifier classes and replacements

Policy rules continue to store prohibited byte sequences in encoded form. Test
fixtures construct them from encoded data as well, so neither policy source nor
CI logs reintroduce the values in plain text.

### Personal and workstation identifiers

- Personal email addresses in tracked content become a non-routable project
  placeholder such as `maintainers@example.invalid`.
- Developer usernames and workstation home paths become role-based text,
  repository-relative paths, or `/path/to/aria-firewall` examples.
- `AGENTS.md` and `CLAUDE.md` stop recording personal Git identity. The local
  repository configuration remains the source of commit identity and is not
  tracked.

### Repository provenance

The canonical HTTPS repository URL and hosted Actions run URLs remain allowed
where they are required to navigate this already-public repository or verify a
specific CI result. Redundant SSH remote strings, personal usernames, and email
metadata are removed.

This exception is intentionally narrow: it permits a valid provenance URL, not
the same owner token in arbitrary prose, package author metadata, shell
examples, or configuration.

### Target environment

- The three target nodes map by stable ordinal to
  `compute-1.example.test`, `compute-2.example.test`, and
  `compute-3.example.test`.
- Short host forms map to `compute-1`, `compute-2`, and `compute-3`.
- Target-environment IPv4 values map into the RFC 5737 documentation range
  `192.0.2.0/24`, preserving host ordinals, prefix lengths, equality, nesting,
  and source/destination relationships.
- Other host-specific labels, paths, and archive member names use the same
  mapping. No random value generation is allowed.

The mapping changes presentation only. It must not change pass/fail status,
generation ordering, policy identity, timestamps, packet counts, or transaction
evidence.

## Current-tree migration

The migration covers every tracked path, including:

- maintained Markdown and package metadata;
- Rust/Python schema examples and test fixtures;
- shell smoke defaults and embedded Python blocks;
- CI scripts and workflow references to committed evidence;
- `docs/evidence/**` path names and textual content;
- tracked generated HTML and archive members under `outputs/**`.

Text is rewritten using one explicit deterministic mapping. Tracked directory
and file names are renamed with `git mv` semantics, then every reference to
those paths is updated. Generated archives are rebuilt from the anonymized
tracked source instead of edited as opaque bytes.

Evidence files remain in place logically and retain their original chronology
and result. Removing generated output or changing the long-term evidence
retention policy remains `DEBT-REPO-001`; ACL-011 does not use hygiene work as a
reason to delete evidence.

## Policy checker design

### Shared rule model

Keep one encoded rule inventory consumed by both repository and payload scans.
Each rule has a stable numeric identifier and an ASCII-fold flag. CI reports
only the affected path/member and rule number.

The implementation may extract shared byte-scanning helpers into one small
module, but must not introduce a source parser or bind checks to implementation
function names.

### Repository scan

`ci/check_blocked_terms.py` continues to enumerate tracked files from Git and
adds:

- path-name scanning before opening a file;
- regular textual/binary-string content scanning;
- archive-member name and content scanning for tracked ZIP/TAR files;
- a narrow, testable allowance for canonical repository and Actions provenance
  URLs.

A prohibited value in an evidence directory is still a failure. There is no
blanket exception for `docs/evidence/**`, tests, plans, or generated output.

### Generated payload scan

`ci/check_payload_terms.py` uses the same rules for:

- ordinary file names and content;
- directory-relative path names;
- ZIP and TAR member names and content;
- nested text visible in Kolla bundles and release archives.

ELF machine code keeps the existing false-positive protection: only extracted
human-readable strings are checked. The rule does not treat arbitrary
compressed or executable bytes as text.

### Provenance allowance

The exception for the canonical public repository and Actions links is applied
to a complete recognized URL token. It must not globally allow the owner token
or skip an entire file. Malformed URLs and the same token outside that URL
shape remain rejected.

## RED behavior coverage

Non-privileged Python tests must prove:

1. every new encoded identifier class is rejected in tracked text;
2. ASCII case variants are rejected where applicable;
3. a prohibited identifier in a tracked path name is rejected;
4. ZIP and TAR member names and textual content are rejected;
5. binary/ELF false-positive behavior remains unchanged;
6. canonical repository and Actions provenance URLs are accepted, while the
   same identifier outside a complete allowed URL is rejected;
7. the payload scanner applies the same rules to directories and archives;
8. scanner diagnostics contain only rule numbers and paths, not decoded
   prohibited values;
9. the anonymized current tracked tree passes the repository scan;
10. rebuilt release/Kolla fixtures pass the payload scan.

Tests exercise public scanner entry points or shared byte/path policy behavior.
They do not parse private implementation structure.

## Migration and commit sequence

1. Add RED policy tests and wire them into `fast-contracts`.
2. Push the RED commit and capture the expected hosted failure caused by the
   missing rule/path/archive behavior.
3. Add the shared policy behavior and deterministic current-tree migration in
   one GREEN batch. Keeping policy and migration together prevents the branch
   from ending a commit with known public identifiers after enforcement exists.
4. Run non-Cargo unit, shell syntax, embedded-Python, blocked-term, payload,
   and diff checks locally.
5. Push GREEN and require exact-head hosted CI, including warning-denied Rust
   and eBPF builds. No local Cargo command is run.
6. Update the authoritative backlog with RED/GREEN commits, exact-head CI, and
   the explicit no-history-rewrite boundary.

The migration may be mechanically large because evidence names and references
are repeated, but it must contain no product behavior change. Review reports
separate policy/checker changes from mechanical replacements.

## Failure behavior

- A decode, file-read, archive-read, or Git enumeration error fails closed.
- A malformed or unsupported archive fails the tracked/payload scan rather than
  being silently skipped.
- A missing generated payload path remains an error.
- Policy diagnostics never print matching content.
- The migration is not considered complete while any tracked path or content
  matches an in-scope rule.

## Explicit exclusions

- no Git history rewrite, force push, tag rewrite, or hosted CI deletion;
- no removal of evidence or generated output under ACL-011;
- no change to ACL, packet, transaction, recovery, or readiness semantics;
- no local Cargo build, check, or test;
- no broad secret scanner, credential rotation, or repository-visibility
  change;
- no closure of `DEBT-REPO-001` or unrelated security risks.

## Acceptance

`REVIEW-ACL-011` is fixed when:

1. all in-scope identifiers are absent from current tracked path names and
   content, including archive members;
2. field evidence remains internally consistent under deterministic aliases;
3. canonical public provenance links still work;
4. repository and generated-payload policies reject every agreed identifier
   class without logging its decoded value;
5. RED behavior is demonstrated on the old scanner and exact-head GREEN CI
   passes every required lane;
6. the backlog states that only current HEAD and future payloads are clean and
   that historical Git objects were deliberately not rewritten.

Executed evidence:

- RED commit `6ed8abc` / Build
  [`30811086605`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30811086605)
  failed `fast-contracts` at the intentionally missing shared policy boundary.
- GREEN commit `af6accb` / exact-head Build
  [`30811728869`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30811728869)
  passed fast contracts, database contracts, clean installation, selected Rust
  behavior, and warning-denied eBPF/userspace/static-agent builds.
- No privileged field execution applies to this repository/payload hygiene
  repair, and none is claimed.

## Design self-review

- The design addresses the real public repository, not only uploaded binaries.
- It keeps the existing evidence semantics and separates retention cleanup.
- It preserves valid repository and CI provenance without creating a global
  allowlist hole.
- It adds executable byte/path/archive behavior instead of static source-shape
  checks.
- It records the unavoidable Git-history limitation and requires separate
  authorization for destructive remediation.
- It does not claim privileged field execution or require local Rust builds.
