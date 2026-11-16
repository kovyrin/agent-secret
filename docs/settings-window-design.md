---
name: Agent Secret Settings
description: Compact native macOS settings for CLI setup and update preferences.
---

# Settings window design

## Overview

This is a scoped reference for the native Settings surface, not a project-wide
brand system. The window lets users inspect CLI status, manage update checks, and
reach repair or diagnostics when needed. Keep routine use quiet, including after
updates; launch and update lifecycle behavior must be verified separately.

The implementation is authoritative:
[SettingsWindowController.swift](../approver/Sources/AgentSecretApproverApp/SettingsWindowController.swift),
[SettingsState.swift](../approver/Sources/AgentSecretApproverApp/SettingsState.swift),
and [SettingsDetailsController.swift](../approver/Sources/AgentSecretApproverApp/SettingsDetailsController.swift).

The reviewed `settings-installed-light.png` and `settings-installed-dark.png`
previews render the actual AppKit window with synthetic state. Their `0.1.3`
version, installed CLI, and enabled update checks are fixture values, not evidence
of a released build, successful installation, or working updater. The opt-in
[preview test](../approver/Tests/AgentSecretApproverTests/SettingsWindowTests.swift)
uses `AGENT_SECRET_SETTINGS_PREVIEW_DIR` to choose its output directory.

## Colors

Use AppKit semantic colors so the surface follows light and dark appearance.
Primary labels use `labelColor`; status, version, helper text, and activity use
`secondaryLabelColor`. Window background, rounded buttons, checkbox, and separators
retain native rendering. The app icon supplies the existing identity color.

Details output uses `textColor` on `textBackgroundColor`. Do not replace these
dynamic colors with sampled screenshot hex values or a separate CSS palette.

## Typography

Use the system font and native control typography. The app name is semibold
(16 pt), section titles are semibold (13 pt), and CLI status is regular (12 pt).
Version, installation-approval helper, update notice, and activity are regular
(11 pt). Details use a semibold summary (13 pt) and selectable monospaced output
(11 pt).

## Layout

The main window normally uses 500 × 350 pt of content, with native title,
close, and minimize controls. A notice increases its height to 380 pt so the
message stays readable. A single column contains the identity header, CLI row,
Updates section, and named Diagnostics section. Three full-width native
separators divide these areas; there is no sidebar or card grid.

Content insets are 26 pt horizontally, 22 pt at the top, and 18 pt at the bottom.
The main stack uses 16 pt gaps. The icon is 44 pt square; its text sits 12 pt away.
CLI status stays beneath its label, with Install or Repair aligned to the right.
Check for Updates remains within Updates, below the checkbox and approval
explanation. Diagnostics follows the third separator, with its heading on the
left and Run Diagnostics on the right. Optional progress and activity sit between
the heading and button.

Details use a separate resizable window (initial content 500 × 320 pt; minimum
window size 420 × 260 pt), with a summary, scrollable output, and trailing Done
button. Long output belongs here rather than expanding the Settings window.

## Elevation & Depth

Use the native window frame and control treatment. The content has no custom
shadows, raised cards, gradients, or overlays; spacing and separators establish
the hierarchy.

## Shapes

Action buttons use AppKit's rounded bezel. Separators use `NSBox.separator`.
Details output uses the scroll view's native bezel border. Leave corner geometry
and focus treatment to AppKit.

## Components

- **CLI status:** Installed, Not installed, Repair needed, or App needs
  reinstalling. The missing state shows Install; the other states show Repair,
  disabled when the bundled tool is unavailable.
- **Updates:** A native automatic-check checkbox, the explanation “You approve
  every installation.”, and Check for Updates. When updates are not configured,
  update controls are disabled and a short notice explains why.
- **Secondary actions:** Repair remains beside CLI status; Run Diagnostics stays
  in its own named section. Their output does not become the main window's
  default content.
- **Activity:** Busy state disables action controls and shows a small spinner
  (16 pt). Diagnostics-section activity truncates at the tail; update notices
  allow two lines.
- **Details:** Output is read-only, selectable, and vertically scrollable. Done
  is the default Return-key action. These presentation rules do not establish
  whether an installation or diagnostic operation succeeded.

## Do's and Don'ts

- Do preserve the compact, native hierarchy in both macOS appearances.
- Do keep installation approval distinct from automatic update discovery.
- Do verify actual actions and launch behavior separately from fixture previews.
- Don't add a prominent repair prompt, persistent diagnostic dump, or success
  celebration to the normal installed state.
- Don't promote this surface's dimensions or composition into global app rules.
