# Approval UI redesign verification

Implementation and synthetic validation: 2026-10-21, macOS on Apple Silicon,
Swift 6.1, with the macOS 14 deployment target preserved.

## Delivered behavior

The production SwiftUI/AppKit prompt now uses the reviewed context/consequence
layout, provider/account groups, full references behind disclosures, a scope
selector, and two pinned decisions. Resource and Request details disclosures
use a button across the entire label row, with hover feedback and an explicit
expanded/collapsed accessibility value.

The progress bar derives from the original request TTL, including queue time.
Sessions distinguish approval time, subsequent access duration, and read limit.
Legacy requests omit the proportional bar and identify an unavailable read
limit. Expiration still completes timeout and closes; no persistent expired
screen was added. The broker's access policy is unchanged.

## Native capture matrix

These PNGs are AppKit bitmap captures of the production `ApprovalRequestPanelView`
inside a native window. They are not browser approximations or screenshots of
the HTML prototype. All requests are synthetic; no daemon, provider, credential,
or installed application participates in capture.

<!-- markdownlint-disable MD013 -->

| Variant | Light | Dark |
| --- | --- | --- |
| One secret | [Capture](images/approval-redesign/v1-light.png) | [Capture](images/approval-redesign/v1-dark.png) |
| Multiple accounts | [Capture](images/approval-redesign/v2-light.png) | [Capture](images/approval-redesign/v2-dark.png) |
| Bitwarden source/token scope | [Capture](images/approval-redesign/v3-light.png) | [Capture](images/approval-redesign/v3-dark.png) |
| Item metadata | [Capture](images/approval-redesign/v4-light.png) | [Capture](images/approval-redesign/v4-dark.png) |
| Bound session | [Capture](images/approval-redesign/v5-light.png) | [Capture](images/approval-redesign/v5-dark.png) |
| Broad scope | [Capture](images/approval-redesign/v6-light.png) | [Capture](images/approval-redesign/v6-dark.png) |
| Environment-printing caution | [Capture](images/approval-redesign/v7-light.png) | [Capture](images/approval-redesign/v7-dark.png) |
| Override and mutable executable | [Capture](images/approval-redesign/v8-light.png) | [Capture](images/approval-redesign/v8-dark.png) |

<!-- markdownlint-enable MD013 -->

Additional native captures:

- [Constrained 760 × 600 visible frame](images/approval-redesign/constrained-long-content.png):
  stacked body, long reason/arguments, seven resources, and pinned decisions.
- [Amber at 60 seconds](images/approval-redesign/remaining-60.png).
- [Red at 15 seconds](images/approval-redesign/remaining-15.png).
- [Queued request with 30 of 120 seconds left](images/approval-redesign/remaining-30.png).
- [Legacy session without new metadata](images/approval-redesign/legacy-session.png).

The capture harness uses the presenter's actual initial sizing and production
view. Review found and corrected primary-button contrast and duplicated limit
text. The selected limit now remains beside the actions when content scrolls.

Reproduce from the repository root:

```bash
mise exec -- env AGENT_SECRET_UI_CAPTURE_DIR=/tmp/agent-secret-ui-captures \
  swift test --package-path approver --filter ApprovalPanelVisualTests
```

Three capture tests passed, producing 21 images. The accessibility interaction
test is deliberately opt-in and skipped in this command.

## Behavioral proofs

The new owning tests cover additive payload metadata for all three operations,
fractional TTLs, legacy/missing/null/invalid decoding, deadline thresholds and
ceiling seconds, partial queue progress, selected-scope decisions, capability
gating, exact reuse counts, separate session limits, complete resource identity,
ordering, and combined warnings.

Panel interaction tests exercise exact-deadline clicks, late wake/ticks,
single completion, and selection without submission. The socket regression
proves timeout promotes the next queued request without waiting for UI input
and preserves its original TTL. Presenter tests cover screen bounds, actual
width measurement, and stable geometry across ticks. Decision specifications
used by the visible buttons verify Escape on Deny and no default Return action.

Focused Go approval, Swift protocol/presentation/geometry tests passed during
their implementation slices. The synthetic nonvisual smoke passed with
`approver-smoke-ok`:

```bash
mise exec -- swift run --package-path approver agent-secret-app-smoke
```

Repository-wide checks:

| Check | Result |
| --- | --- |
| Go formatting, vet, golangci-lint | Passed, zero issues |
| All Go tests and race tests | Passed |
| Go coverage gate | Passed: 81.0% total; approval package 87.6% |
| SwiftFormat and strict SwiftLint | Passed: 130 files, zero violations |
| Full Swift suite | Passed: 116 tests, five opt-in tests skipped |
| Synthetic nonvisual smoke | Passed |
| Native capture tests | Passed: three capture tests, 21 PNGs |
| `mise run build` | Passed: local ad-hoc signed app bundle |
| Secret scan | Passed, no leaks |
| Shell, TOML, Markdown, workflow checks | Passed |

`mise run lint` exited at `govulncheck`: it reported 11 standard-library
advisories against the repository's existing Go 1.26.5 pin. The same pin is
present at planning baseline `80ce745`; this change does not modify the Go
toolchain or dependencies. Remaining lint stages were run separately and passed
as listed above. A Go security patch upgrade is separate follow-up work; the
full lint command is not green.

## OS validation limits

Native rendering and automated state/geometry checks do not establish every
operating-system interaction. Native accessibility tests can be attempted with:

```bash
mise exec -- env AGENT_SECRET_NATIVE_UI_TESTS=1 \
  swift test --package-path approver \
  --filter 'ApprovalPanelDisclosureTests|ApprovalPanelVisualTests'
```

This machine's XCTest process exposes an empty native accessibility tree; the
tests report a skip when that happens. Computer-use attachment and window
screen capture were also unavailable. No successful manual pointer-hover,
full-row click, expanded-resource, once/reuse keyboard traversal, or VoiceOver
walkthrough is claimed. Those controls use native buttons/pickers; their state
and submitted decision mapping have automated proofs, while actual OS input
remains a manual follow-up.

Increase Contrast, Reduce Motion, hardware sleep/wake, display migration, and
full-screen Spaces were not exercised manually. The UI reads system contrast
and motion preferences, refreshes from the deadline on wake/reactivation, and
observes visible-frame changes. Existing trust, screen-lock, activation, and
modal behavior remain in their original owners.

## Delivery boundary

Changes are local commits. No application was installed, daemon restarted,
secret fetched, branch pushed, pull request opened, or release published.

The local build is `_dist/Agent Secret.app`. Implementation commits are:

- `e620810`: plan, internal grilling decisions, and invariants.
- `e656d5e`: validated optional timing/read-limit metadata and compatibility.
- `a145b05`: countdown, scope, consequence, grouping, and warning models.
- `a13a9d5`: adaptive native panel and presenter geometry.
- `e358b43`: progress integration and single-completion deadline lifecycle.
- `f4f4aad`: full-row disclosure buttons and hover feedback.
- `8534e5e`: visible decision wiring, pinned limits, and button contrast.
- `76b532a`: removal of superseded presentation views.
- `1b3f557`: synthetic native capture harness and relative smoke deadlines.

This verification record, release notes, and screenshots are delivered in the
following documentation commit.
