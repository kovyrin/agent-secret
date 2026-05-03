# Simplification Plan

Status: active cleanup ledger.

Last updated: 2026-05-03.

## Goal

Reduce the codebase by at least 30% while preserving the security posture that
is explicitly promised in `docs/threat-model.md`.

This document is the working memory for the simplification pass. Update it when
the baseline changes, when a cleanup chunk lands, or when a proposed deletion is
accepted or rejected.

## Baseline

Baseline commit: `81d4d80`.

Measured selected tracked files: Go, Swift, shell, Markdown, YAML, and TOML.

```text
total selected LOC: 39,228
production area LOC: 13,239
test LOC: 17,354
script LOC: 3,123
docs LOC: 5,512
```

Target selected LOC after cleanup: at most `27,459`.

Required reduction: at least `11,769` LOC.

Current selected LOC: `38,847`.

Cumulative reduction from baseline: `381` LOC.

Remaining reduction needed: `11,388` LOC.

Measurement command:

```sh
git ls-files | awk '
/\.go$/ {go[++g]=$0; next}
/\.swift$/ {swift[++s]=$0; next}
/\.sh$/ {sh[++h]=$0; next}
/\.md$/ {md[++m]=$0; next}
/\.(yml|yaml|toml)$/ {cfg[++c]=$0; next}
END {
  for (i=1;i<=g;i++) print go[i];
  for (i=1;i<=s;i++) print swift[i];
  for (i=1;i<=h;i++) print sh[i];
  for (i=1;i<=m;i++) print md[i];
  for (i=1;i<=c;i++) print cfg[i];
}' | while IFS= read -r file; do wc -l < "$file"; done |
  awk '{sum += $1} END {print sum}'
```

## Preserved Security Contract

Cleanup must preserve these invariants:

- Raw secret values are never printed, logged, audited, or documented.
- The daemon resolves secrets only after a valid approval or reusable approval
  match.
- Approval remains bound to request ID, nonce, TTL, command argv, executable
  identity, cwd, secret refs, account scope, and override behavior.
- The daemon accepts exec and stop requests only from trusted Agent Secret CLI
  executables.
- The CLI accepts secret-bearing responses only from a trusted Agent Secret
  daemon.
- The native approver renders requests only from a trusted Agent Secret daemon.
- Protocol frames keep size, version, type, timeout, nonce, and request ID
  checks appropriate to the lifecycle phase.
- Every secret delivery attempt has value-free audit metadata before raw values
  are delivered to a child process.
- Release and install tooling reject artifacts that do not satisfy the product
  signing, notarization, Team ID, and bundle ID contract.

## Reduction Strategy

Cut size in this order:

1. Delete historical review artifacts and redundant docs that are not part of
   the product contract.
2. Collapse repetitive tests into invariant-level tests.
3. Remove shell-script adversarial fixtures that protect helper-tool edge cases
   outside the threat model.
4. Simplify production code where multiple layers enforce the same invariant.
5. Re-run the full verification set after each meaningful chunk.

Do not delete a regression test unless one of these is true:

- A smaller test still covers the same threat-model invariant.
- The case is explicitly out of scope in `docs/threat-model.md`.
- The test only pins implementation structure rather than product behavior.
- The test duplicates lower-level coverage without adding a new boundary.

## Candidate Cuts

Daemon, broker, and protocol tests:

- Current signal: high repetition.
- Target cut: 2,500-3,500 LOC.
- Notes: keep lifecycle and trust-boundary tests. Collapse duplicate race and
  payload-shape fixtures.

Installer and release shell tests:

- Current signal: high fixture cost.
- Target cut: 1,500-2,500 LOC.
- Notes: keep artifact trust contract. Remove helper-tool hardening fixtures
  outside the model.

Swift approver tests:

- Current signal: implementation-heavy.
- Target cut: 1,000-1,500 LOC.
- Notes: keep protocol, peer trust, expiry, and display-safety tests. Trim
  layout and internal-concurrency pinning.

Production daemon, client, and approval code:

- Current signal: layered invariants.
- Target cut: 1,500-2,500 LOC.
- Notes: prefer one clear enforcement point per boundary.

Installer and release scripts:

- Current signal: defensive sprawl.
- Target cut: 1,000-1,500 LOC.
- Notes: preserve release contract but reduce bespoke guard code.

Docs:

- Current signal: historical debris.
- Target cut: 500-1,500 LOC.
- Notes: keep threat model, README, release process, and configuration docs.

## Progress

2026-05-03:

- Commit: `7b0705e`.
- Change: add simplification ledger and model discipline.
- LOC delta: +191.
- Verification: `markdownlint`.

2026-05-03:

- Commit: pending.
- Change: remove historical review report and fake `awk` trust fixture.
- LOC delta: -572.
- Verification: pending.

## Current Decisions

- Keep `docs/threat-model.md` as the security contract.
- Treat complexity as a security and release-readiness risk.
- Prefer fewer black-box security invariants over many narrow adversarial
  fixtures.
- Do not run another open-ended vulnerability review during this cleanup pass.

## Next Cleanup Pass

Start with documentation and shell-test simplification because those cuts are
lowest risk and clarify the target shape before production code changes.

Initial candidates:

- Remove or archive `docs/release-code-review-round-4-2026-05-03.md` if it is
  not needed in the product repo.
- Review `scripts/test-uninstall.sh` and `scripts/test-install.sh` for
  helper-tool path hijack fixtures that exceed the updated threat model.
- Review Swift UI layout/concurrency tests for cases that pin implementation
  rather than product-visible approval safety.
- Review daemon protocol tests for duplicate empty, malformed, and correlation
  cases after the trust-boundary coverage is identified.
