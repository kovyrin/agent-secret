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

## Local appearance investigation, 2026-10-22

Running the capture command below on macOS 26.6.2 reproduced the dark gray
sidebar and account headers from the installed prompt. In Aqua appearance,
AppKit's `underPageBackgroundColor` resolved to gray 0.588 with alpha 0.898;
the saved PR captures showed a much lighter background. The system color is
therefore unsuitable as a stable, opaque sidebar surface. Apple's
[color documentation](https://developer.apple.com/documentation/appkit/nscolor/underpagebackgroundcolor)
describes it as the backdrop beneath a window's views, rather than a card fill.

The production presenter also explicitly set `hasShadow = false`. The bitmap
capture harness drew only the hosting view and constructed its own window, so
the captures did not verify production window configuration or compositor
shadows. Apple's
[shadow documentation](https://developer.apple.com/documentation/appkit/nswindow/invalidateshadow())
provides the native mechanism for recomputing the shadow from the window shape.

The focused regression command is:

```bash
mise exec -- swift test --package-path approver \
  --filter ApprovalPanelAppearanceTests
```

Before the fix, it failed on the disabled production shadow, the gray light-mode
sidebar, its non-opaque alpha, and the excessive surface contrast. Dark-mode
surface checks passed. These checks do not prove a WindowServer shadow is
visible on the desktop; that still requires inspecting the installed prompt.

The fix enables and invalidates the native window shadow, uses the opaque
control background for the main surface, and supplies opaque sidebar shades
for light and dark appearances. The capture harness now uses the production
window factory. The focused regressions pass, including high-contrast color
appearances. A new local capture run passed all three rendering tests and
produced 21 PNGs; the light rendering again matches the bright saved PR palette.

`mise run lint` passed, including 122 Swift tests with five opt-in skips and no
failures. The development app was rebuilt and installed into `/Applications`;
signature verification and `agent-secret doctor --json` passed. A single-secret
child presence check returned `smoke-read-ok` with exit 0 without printing the
value. The user inspected the installed prompt and confirmed that both the
native shadow and brighter sidebar look fixed. Automated native UI inspection
timed out, so this desktop appearance confirmation is human verification.

The session sidebar now shows only access duration and read limit. The approval
countdown remains in the header, avoiding a second copy of the same deadline.
After this removal, the full Swift suite and Swift/Markdown lints passed, and
the native capture run produced 21 PNGs. A live session presence check returned
`session-smoke-read-ok`; the session was then explicitly destroyed.

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

The README uses fresh command, session, and metadata captures with automatic
light/dark selection. Its synthetic metadata fixture matches the daemon's
item-level reference and item-name alias; its session fixture uses the same
original TTL for approval and subsequent access, matching the current payload.

Reproduce from the repository root:

```bash
AGENT_SECRET_UI_CAPTURE_DIR=/tmp/agent-secret-ui-captures mise exec -- \
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

A separate native disclosure fixture uses the production disclosure style and
presenter hosting policy in a constrained 400 × 240 window. It repeatedly
expands and collapses long content, verifies the content's appearance and
disappearance, and checks that the host and window frames remain unchanged.
The clock test is named separately to reflect what it exercises. This proof
drives a SwiftUI binding; it does not simulate pointer or accessibility input.

Operation-specific copy tests verify that metadata lookups describe returned
item names and field metadata, with an `Item` disclosure label. Command and
session prompts retain their environment-delivery notes and `Injected as`
labels. The refreshed light/dark metadata captures show the corrected footer.

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
| Go coverage gate | Passed: 81.1% total; approval package 87.6% |
| SwiftFormat and strict SwiftLint | Passed: 132 files, zero violations |
| Full Swift suite | Passed: 119 tests, five opt-in tests skipped |
| Synthetic nonvisual smoke | Passed |
| Native capture tests | Passed: three capture tests, 21 PNGs |
| `mise run build` | Passed: local ad-hoc signed app bundle |
| Secret scan | Passed, no leaks |
| Shell, TOML, Markdown, workflow checks | Passed |
| `mise run lint` | Passed, including the vulnerability scan |

The initial contributor review found 11 standard-library advisories against
the existing Go 1.26.5 pin. The [official Go release history](https://go.dev/doc/devel/release#go1.26.0)
lists Go 1.26.10 (2026-10-19) as the latest patch on the same release line,
including the latest `crypto/x509` security fix. The follow-up upgrades the
toolchain pin to that patch without changing the module's Go language version
or dependencies. The complete `mise run lint` now passes, and `govulncheck`
reports no vulnerabilities.

## OS validation limits

Native rendering and automated state/geometry checks do not establish every
operating-system interaction. Native accessibility tests can be attempted with:

```bash
AGENT_SECRET_NATIVE_UI_TESTS=1 mise exec -- \
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
- `e3784dc`: native captures and implementation verification.
- `564d054`: README light/dark captures and daemon-consistent fixtures.
- `26023bf`: actual disclosure expansion/collapse geometry proof.
- `bb1f0d8`: operation-specific metadata copy, tests, and refreshed captures.

The Go security patch, release notes, and updated verification record are
delivered in the following follow-up commit.
