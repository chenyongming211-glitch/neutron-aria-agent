# RISK-CI-001 Immutable GitHub Action Pins Design

**Status:** approved design; implementation pending

**Scope:** external `uses:` references in `.github/workflows/*.yml`

## 1. Objective

Make every externally executed GitHub Action immutable at review time and keep
it immutable after future workflow edits. A semantic tag or branch must never
select different action code without a repository commit and hosted CI review.

This batch changes workflow dependency identity only. It does not change job
permissions, triggers, conditions, Rust versions, artifact contents, release
authority, or the current fast/build lane split.

## 2. Current Exposure

The Build workflow already pins `actions/checkout`, `actions/cache`,
`actions/download-artifact`, and `softprops/action-gh-release` to complete
commit SHAs. Eight external executions remain mutable:

- two `dtolnay/rust-toolchain@stable` uses;
- one `dtolnay/rust-toolchain@master` use; and
- five `actions/upload-artifact@v4` uses.

The first five checkout/cache replacements removed the Node.js 20 warning, but
that partial repair does not constrain the eight references above.

## 3. Selected Contract

Every external action or reusable workflow reference under
`.github/workflows/` must use this shape:

```text
owner/repository[/path]@<40 lowercase hexadecimal commit SHA>
```

Repository-local actions beginning with `./` are exempt because their content
is already fixed by the checked-out repository commit. A future `docker://`
action is not silently exempt: it must use an immutable digest and gain an
explicit validator case before it can enter the workflow.

The implementation adds one small public structural validator rather than a
YAML or Rust source parser. It reads workflow lines containing `uses:`, removes
YAML quoting and inline comments, classifies local versus external references,
and rejects every unsupported or mutable external form. The validator returns
the file, line, and offending reference so a failure is actionable.

The validator is exercised in the existing Cargo-free `fast-contracts` job.
Mutation tests must prove that `@v4`, `@stable`, `@master`, a short SHA, an
uppercase SHA, and a missing `@` are rejected, while a local action and a full
lowercase SHA are accepted. Tests bind only to the public `uses:` identity
contract, not to job order or private helper spelling.

## 4. Pin Selection and Toolchain Preservation

Implementation resolves each current mutable ref against its official GitHub
repository, records the reviewed commit, and verifies that the commit belongs
to the intended upstream ref before editing the workflow. The workflow keeps a
human-readable upstream version/ref comment next to each SHA.

Pinning `dtolnay/rust-toolchain` must not rely on the former ref name to select
the compiler:

- both stable installations explicitly set `toolchain: stable`;
- the userspace installation retains
  `targets: x86_64-unknown-linux-musl`; and
- the eBPF installation retains `toolchain: nightly-2026-07-14` and
  `components: rust-src`.

The five upload steps retain their names, paths, conditions, retention periods,
and artifact publication policy exactly.

## 5. Update Governance Boundary

The immutable execution risk is closed by reviewed pins plus the no-regression
validator. Automated refresh is a separate maintenance mechanism.

GitHub reads `.github/dependabot.yml` from the default branch. This repository's
default branch is currently `main`, while the sole development and delivery
branch for this line is `v0.9-neutron-agent`. Adding a Dependabot file only to
the delivery branch would not activate it and therefore must not be reported as
working automation.

Until default-branch governance changes, action updates are explicit reviewed
commits on `v0.9-neutron-agent`. Default-branch Dependabot activation remains a
recorded governance follow-up and is not implemented by this batch.

## 6. RED/GREEN Evidence

RED adds the validator tests and fast-lane wiring before any workflow pin is
changed. The real workflow assertion must fail on the eight known mutable
references.

GREEN replaces only those references, preserves the explicit toolchain and
artifact inputs, and makes the same tests pass. Hosted acceptance requires:

- `fast-contracts` executes the mutation suite and real-workflow validator;
- Rust behavior still installs the intended stable toolchain;
- eBPF still builds with `nightly-2026-07-14`;
- warning-denied userspace and agent builds pass;
- the 448-byte legacy eBPF stack gate passes; and
- artifact steps retain their prior conditional behavior.

No local Cargo command is run. No privileged or field evidence applies.

## 7. Closure

`RISK-CI-001` may be marked fixed for immutable action execution when all
external `uses:` references pass the validator at an exact green head. The
default-branch automated-refresh follow-up remains explicitly pending and must
not be described as enabled.
