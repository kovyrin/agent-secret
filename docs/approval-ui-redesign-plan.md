# Approval UI redesign plan

Status: planned; application implementation has not started.

Planning baseline: commit `80ce745`, reviewed on 2026-10-21.

## Outcome and agreed scope

Rebuild the native approval prompt around the reviewed 2b design: request
context on the left, consequences and decisions on the right, quiet surfaces,
explicit account/provider scope, and expandable references. Support all eight
reviewed examples using real request metadata rather than example-specific
logic.

The latest variants reference is
[2b Variants](http://127.0.0.1:51569/2b%20Variants.dc.html).
The original countdown reference is
[Countdown Prototype](http://127.0.0.1:57412/Countdown%20Prototype.dc.html).
These are local design references, not build or runtime dependencies. Record
synthetic visual evidence during implementation so the localhost servers are
not required for future maintenance. Do not copy consumer-specific accounts,
reasons, paths, or references from the prototypes into repository fixtures.

Two explicit scope decisions supersede earlier recommendations:

- Include the progress bar; the user finds it useful. Add authoritative request
  duration metadata so it represents the original request lifetime accurately.
- Omit the persistent expired screen. At expiration, finish with timeout and
  close, using the existing modal/controller lifecycle. No new post-expiration
  window, dismissal flow, queue protocol, or long-lived approver process.

Keep SwiftUI/AppKit, the macOS 14 deployment target, Unix socket transport,
existing trust checks, and the existing broker enforcement. No web view, new
UI framework, live provider access, installed-app replacement, daemon restart,
release publication, or credential changes belong to this implementation.

## Current implementation facts

- `ApprovalRequestPanelView` already ticks once per second, guards decisions
  against `expiresAt`, and completes only once. `ApprovalController` checks
  expiration again before submission; the Go approver also enforces it.
- `AppKitApprovalPresenter` owns a borderless modal window and its geometry.
  Existing sizing tests protect against delayed layout jumps. Its current
  720-point minimum and 200-point reserved section assume the old layout.
- The request view model already escapes display metadata, renders exact argv,
  supports inspection, handles verified session binding, and identifies
  direct `env`/`printenv` requests. Preserve those owners and protections.
- The daemon sends resource provider/account/source/token-alias metadata,
  expiration, reuse count, session access duration, and session binding.
  It does not send the original request TTL or session maximum reads to the
  approver today.
- All exec requests currently permit the operator to choose reusable approval,
  including Bitwarden requests. Reuse ends at the original request deadline;
  its use count includes the initial delivery. Session access receives a fresh
  lifetime after approval succeeds and is separately limited by reads.
- The SDK metadata path retrieves an item and constructs a value-free response.
  Promise that secret values are not returned, not that the SDK never obtains
  an item containing them.

Source owners:

- `internal/daemon/approval/approval_protocol.go` and its tests.
- `internal/daemon/approval/socket_approver.go` for queue/decision behavior.
- `internal/daemon/broker/broker.go`, `session_store.go`, and session tests.
- `internal/policy/policy.go` for reuse enforcement.
- `approver/Sources/AgentSecretApprover/{Models,Presentation,Runtime}`.
- `approver/Tests/AgentSecretApproverTests/{Protocol,Presentation,Runtime}`.
- `approver/Sources/AgentSecretApproverSmoke` for isolated native walkthroughs.

## Internal grilling and settled decisions

The requested grilling was conducted internally, with repository facts taking
the place of questions to the user. Each round settled prerequisites for the
next round. No product decision remains blocked on a user answer.

1. **Scope and architecture.** Can this stay native without changing access
   policy? Yes. Replace presentation and add two metadata fields. Preserve
   broker policy and timeout-and-close behavior. The progress bar is in scope;
   a persistent expired screen is explicitly excluded.
2. **Truthful permission language.** Does each statement describe an enforced
   boundary? Use the revised copy and operation-specific timelines. Read-only
   reasons remain the agent's stated intent. Preserve actual scope inspection;
   do not imply that arbitrary Python or shell input is reviewed or restricted.
3. **Contract and compatibility.** Can the bar and session limits use existing
   fields? Not completely. Add typed TTL and session-read metadata; do not parse
   flags from argv or invent defaults when older daemons omit them. Keep the
   wire version and decision schema unchanged with additive optional fields.
4. **Selection and time.** Can a countdown rerender widen approval or reset its
   selection? Keep scope selection as request-local view state, defaulting to
   once. Derive time from the deadline on every tick; never decrement a local
   counter. Selecting reusable scope is not itself an approval.
5. **Identity and warnings.** Can identical display labels merge distinct
   scopes? Group using structured provider/account/source/token-alias keys,
   never formatted strings. Keep complete references and argv inspectable.
   Warning combinations must not suppress one another. Do not introduce shell
   parsing or restrict Bitwarden reuse based on the example variant.
6. **Geometry and accessibility.** Can expanded content hide decisions or move
   them under the pointer? Fit the initial window to the visible screen, then
   scroll content within stable geometry. Keep actions pinned, make scope and
   disclosure controls keyboard accessible, and avoid a global Return action.
7. **Proof and delivery.** Can screenshots alone establish scope correctness?
   No. Add owning contract/state tests alongside each slice, then inspect the
   real native views with synthetic requests. Keep deployment and live secret
   fetches outside the validation path.

## Presentation and interaction contract

### Request context

- Show application identity, operation label, countdown badge, and thin
  horizontal progress bar in a persistent header.
- Show applicable cautions before the headline, followed by the agent's stated
  reason, resource groups, command, folder, and binary. Sessions also show the
  verified bound process; metadata requests describe an item lookup.
- Use the executable basename for exec headlines and verified process metadata
  for session requester identity. Never infer a trusted requester from reason
  text, environment variables, or the name of a nested script.
- Group resource rows by provider and account. For Bitwarden, preserve source
  and token alias separately; a source alias is not necessarily its token alias.
  Preserve first-appearance ordering and each group's original resource order.
- Expand rows to show the complete sanitized reference, account or source/token
  scope, and environment alias. Long aliases and references must remain fully
  inspectable. Preserve existing exact-argv and path inspection capabilities.
- Derive high-scope counts from actual resources and distinct vault identities,
  not the number of account groups. Use provider-appropriate text where there
  is no vault concept. Keep the current six-resource warning threshold.
- Present high-scope, environment-printing, override, and mutable-executable
  warnings together when applicable. Keep detection limited to its existing
  behavior; absence of an environment-printing warning is no safety guarantee.
- Keep reason expansion explicit and preserve the fix preventing selection of
  truncated reason text from drawing outside its container.

### Decisions and consequences

- Exec defaults to `This run`. Offer reusable scope only when the daemon allows
  it and the total use limit exceeds one. Apply the same rule to both providers.
- The segmented control changes the consequence timeline and primary label.
  Only the final Allow button submits `.approveOnce` or `.approveReusable`.
  Echo the displayed daemon-supplied reuse count exactly in reusable decisions.
- Show the original deadline in local time and the total run limit. The button
  label includes the selected scope; the nearby limit remains visible. Full
  deadline precision, date, and time zone are available in request details.
- Metadata uses `Allow lookup`; sessions use `Start session`. Neither offers
  reusable exec scope. Keep decision kind semantics unchanged.
- Sessions separately show approval time remaining, access duration, and total
  read limit. One read means one delivery of the approved session environment,
  not one secret field. Explain duration or read exhaustion, whichever is first.
- Use the revised one-delivery, metadata-only, and process-retention language.
  Describe session duration as starting after approval, never as time remaining
  on the request. Do not promise revocation of values already delivered.
- Escape denies. Do not register Return as the default approval shortcut or
  give the approval button automatic initial focus. Deliberately focused native
  controls remain operable through normal keyboard and assistive input.
- Reuse selection and disclosures remain stable across clock ticks. They reset
  for a different request and are never persisted across approvals.

### Countdown and progress

- Compute `remaining = max(0, expiresAt - now)` and display ceiling seconds as
  `m:ss`. Bar fill is `clamp(remaining / requestTTLSeconds, 0, 1)`.
- Green above 60 seconds, amber at 60 seconds through above 15 seconds, red at
  15 seconds through above zero. At zero, complete timeout and close. Short
  requests legitimately open in amber or red.
- Pair the calm badge's `Answer within` label with `Closing in` in amber/red,
  preserving a textual indication of urgency alongside the changing colors.
- The denominator is the original daemon request TTL, including time already
  spent waiting in the queue. Never start a new timer or refill the bar when
  the prompt opens, a disclosure expands, or the user changes approval scope.
- For sessions, the bar tracks the approval deadline, not the future access
  duration. For reusable exec, choosing reuse does not extend the deadline.
- Keep the existing main/modal-compatible timer. Refresh from the current date
  after wake or application reactivation; a delayed timer must not grant extra
  access. Retain click-time, controller, and daemon expiration checks.
- Use restrained interpolation for bar movement; Reduce Motion uses direct
  updates. Announce meaningful phase changes to VoiceOver without announcing
  every second or stealing focus. Text accompanies the status colors.
- If an older daemon omits total-duration metadata, retain the countdown badge
  and omit the proportional bar rather than draw an invented lifetime.

### Native layout and appearance

- Target an 880-point card with a roughly 340-point consequence column, using
  system fonts and SF Symbols. Apply the reviewed light/dark semantic palette
  and accessible contrast variants rather than inheriting fixed light fills.
- Bound the complete window to the active screen's visible frame with a
  32-point total margin in each dimension. Remove the old unconditional
  720-point minimum and hard-coded reserved action height.
- Use two columns when the card can be at least 800 points wide. Below that,
  stack context and consequences with decisions pinned at the bottom.
- Pin the header and decision controls. Scroll long context; allow long
  consequence content to scroll above pinned decisions. In stacked mode use a
  single body scroll area above decisions. All content remains reachable.
- Measure initial content with the actual chosen width. Preserve presenter
  ownership of geometry and disabled intrinsic-size propagation. Countdown
  updates and disclosure expansion do not resize or recenter the open window.
  Refit only for an explicit screen/available-frame change.
- Preserve the existing window activation, modality, trust, and screen-lock
  preflight behavior. No new focus policy or operating-system support change.

## Additive approval metadata

Add these fields to Go `ApprovalRequestPayload` and Swift `ApprovalRequest`:

<!-- markdownlint-disable MD013 -->

| Wire field | Source and meaning | Compatibility |
| --- | --- | --- |
| `request_ttl_seconds` | Original validated `req.TTL.Seconds()` for exec, metadata, and session requests; fractional seconds preserved. | Optional `TimeInterval` in Swift; missing/null means unknown and hides the bar. |
| `session_max_reads` | Validated `req.MaxReads` on session requests only; omit elsewhere. | Optional `Int` in Swift; missing/null shows `Read limit unavailable` and omits numeric-limit promises. |

<!-- markdownlint-enable MD013 -->

Use protocol version 1: fields are additive, and old Swift decoding ignores
unknown keys. Keep old-daemon/new-UI and new-daemon/old-UI fixture coverage.
Keep the existing required fields required. Reject supplied TTL values outside
the finite 10-to-600-second range and read limits outside 1 through 100; do not
clamp them into a different displayed permission. Type mismatches also fail
decoding. The UI uses read limits only for session presentation.

Legacy missing session limits remain approvable under the existing daemon
policy, but the UI explicitly states that the limit is unavailable. Never
substitute one read, infer unlimited access, or parse display arguments to
recover the count. Existing access-duration and binding fallbacks remain
explicit when absent.

Update shared wire fixtures with synthetic values and preserve a deliberate
legacy fixture. Update programmatic initializers and smoke-request construction
alongside the decoder. No new secret-bearing fields or decision fields.

## Behavioral invariants and owning proofs

Add these proofs in the first implementation batch that changes each owner.
Existing passing tests are a baseline, not a substitute for the task-specific
counterexamples below.

<!-- markdownlint-disable MD013 -->

| Invariant | Realistic counterexample | Owner | Narrow proof |
| --- | --- | --- | --- |
| Displayed duration/read limits come from validated broker metadata. | A profile supplies two reads while argv omits the flag; an older daemon omits the new fields. | Go payload builders; Swift decoder. | Builder tests for all operations, round-trip fixtures, missing/null/invalid values, and legacy decoding. |
| Selecting scope cannot approve or reset on a tick. | Choose reuse, expand a row, then cross the amber threshold. | Request-local selection and decision specification. | New state tests assert unchanged selection/disclosure and zero submission until Allow. |
| Submitted scope equals what the user sees. | Total reuse limit is 1, 2, or 20; metadata/session erroneously offers reuse. | Decision specification; existing controller. | Initial once selection, capability gating, all operation mappings, and exact reusable count echoed. |
| Expiration cannot deliver access or wait for screen dismissal. | Click at the exact deadline; timer and click arrive together; machine wakes after expiry. | Existing expiration model, panel completion, controller, daemon queue. | Extend deadline-equality, delayed-tick, duplicate-completion, and queued-request regressions; isolated socket proof releases the queue without UI input. |
| Bar represents the original request window. | A two-minute request is shown after ninety seconds in the queue. | Countdown presentation model. | Assert 30 seconds and 25% fill; test fractional values, bounds, absent metadata, thresholds at 60/15/0, wake, and session approval versus access time. |
| Resource identity and complete scope survive grouping. | Same vault/item in two accounts; same Bitwarden UUID under distinct sources; long sectioned references. | Resource presentation model. | Structured group-key, ordering, complete-reference, token-alias separation, and exact-argv inspection tests. |
| Warnings compose without losing information. | Six secrets, direct `env`, an override, and a mutable executable coexist. | Warning presentation. | Combination test plus threshold tests at five/six and exact executable identity. |
| Layout changes cannot hide decisions or replay a decision. | Many expanded rows, narrow/short screen, or phase transition while Allow is focused. | Presenter geometry and native panel. | Native sizing/state tests plus synthetic walkthrough with visible pinned controls and single recorded decision. |
| Only metadata enters UI, logs, fixtures, and evidence. | A copied prototype includes private project paths; controls render unsanitized bidi text. | Existing sanitizers, inspection, smoke logger. | Preserve escaping coverage and decision/log value-free assertions; use entirely synthetic fixtures and screenshots. |

<!-- markdownlint-enable MD013 -->

## Implementation slices

Implement sequentially as focused commits once implementation is authorized.
Each slice includes its owning tests before or with production changes.

1. **Approval metadata contract.** Add the two payload fields, Swift decoding,
   programmatic initializer support, compatibility behavior, and shared/legacy
   fixtures. Extend `approval_protocol_test.go` and
   `ApprovalRequestDecodeTests.swift`. Keep broker access policy unchanged.
2. **Presentation state and truthful copy.** Adapt the existing view model for
   provider/account groups, warnings, operation timelines, selected scope,
   session statistics, absolute deadline, and countdown/bar state. Use small
   local value types where needed; no generic workflow engine or new package.
   Add boundary, identity, copy, selection, and decision tests at their owners.
3. **Native panel and geometry.** Replace the old summary/reason treatment,
   resource views, and three-button row with the reviewed layout, disclosures,
   scope control, Allow/Deny buttons, and adaptive scrolling. Update style and
   presenter sizing together; preserve native inspection. Add sizing, focus,
   initial-layout stability, and decision-wiring proofs in this slice.
4. **Countdown and progress integration.** Connect the badge/bar phases to the
   existing deadline checks, including wake/reactivation and Reduce Motion.
   Preserve immediate timeout-and-close and existing IPC. Add timer/click race
   and queue regression proofs; keep phase changes from moving controls.
5. **Native evidence and release documentation.** Extend the existing smoke
   executable/fixtures only as needed to render every reviewed variant with
   the production presenter. Capture light/dark and constrained-screen
   evidence; fix observed issues, not speculative variations. Add a next
   `Pending` changelog section, update relevant approval screenshots/copy in
   `README.md` and `docs/images`, and record the verification results here.

Do not perform a separate broad refactor of the controller, queue, resolver,
installer, or release system. Remove superseded presentation-only code when
its replacements land, after checking references and inspection/test callers.

## Validation and completion criteria

Use `mise` for the project toolchain. During implementation, run the focused
Go approval tests and focused Swift protocol/presentation/runtime tests after
their owning slice. At the final candidate run `mise run lint` and
`mise run build`; these are required repository checks. The lint task already
runs Go, race, coverage, vulnerability, secret, formatting, Markdown, and Swift
checks, so do not repeat broad suites without a new failure or change.

Representative focused commands, run from the repository root:

```bash
mise exec -- go test ./internal/daemon/approval
mise exec -- swift test --package-path approver --filter ApprovalRequestDecodeTests
mise exec -- swift test --package-path approver \
  --filter ApprovalControllerExpirationTests
mise exec -- swift test --package-path approver \
  --filter AppKitApprovalPresenterSizingTests
mise exec -- swift run --package-path approver agent-secret-app-smoke
```

Run new presentation tests by their owning test-class filters as they land.

Run the existing nonvisual smoke executable and native visual requests using
its in-memory `SmokeDaemonClient`, not the installed daemon or live providers.
Use relative-to-now synthetic deadlines in the smoke path; do not add a fake
clock, pause button, or deadline override to the shipped app. Deterministic
time injection belongs in unit tests.

Native evidence must cover:

- All eight variants in light and dark appearance, including actual disclosure
  expansion and once/reuse selection changes. Test Bitwarden with reuse too.
- A standard laptop visible frame and a constrained 760-by-600-point visible
  frame, with long reason/argv/alias/reference content and expanded groups.
- Calm, amber, red, and timeout; a queued request with partial progress; a late
  click; and a second request becoming available after the first times out.
- Keyboard traversal, no global Return approval, Escape denial, VoiceOver
  labels/order, Increase Contrast, Reduce Motion, and no unexpected layout jump.
- Missing optional metadata from a legacy daemon, including the honest read
  limit fallback and countdown without a fabricated proportional bar.

Model tests do not prove native foreground behavior or visual geometry. Record
observed OS behavior with sanitized evidence and commands. If a hardware/OS
scenario cannot be exercised, state the limitation and the nearest automated
proof instead of claiming it passed. Live provider tests remain opt-in and
are not required to approve this UI change.

Completion means the scoped UI and progress bar work through production native
views, the invariant proofs and required checks pass, evidence is recorded,
and release notes describe actual delivered behavior. Report exact commits,
checks, and remaining limitations. Opening, merging, installing, and publishing
are separate delivery actions, not implied by this plan.
