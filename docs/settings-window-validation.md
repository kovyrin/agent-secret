# Settings window validation

## Launch routing observations

On 2026-11-16, a separate, temporary AppKit probe on macOS 27.2 recorded launch
callbacks without opening a window, registering a background item, installing an
app, or contacting a provider. It used `NSWorkspace.OpenConfiguration` with
`activates = false`. Login and service cases supplied a synthesized open-app
Apple event whose `keyAEPropData` contained the corresponding enum code.

| Launch | Observed callback order | Default launch | Origin at completion |
| --- | --- | --- | --- |
| Normal workspace open | will finish, untitled open, did finish | true | none |
| Login item | will finish, did finish | true | `lgit` |
| Service item | will finish, did finish | false | `svit` |

The untitled-open callback can precede the launch-completion notification.
Settings must record that intent and defer presentation until the default-launch
information is available. Restored or service launches must stay quiet. An
explicit reopen is handled separately. Do not infer user intent from a changed
version number.

The probe source and metadata logs from this local observation are under
`/tmp/agent-secret-settings-launch-probe`. The recorded invocations were:

```sh
probe=/tmp/agent-secret-settings-launch-probe/Probe.app/Contents/MacOS/Probe
"$probe" --launch normal /tmp/agent-secret-settings-launch-probe/normal.log
"$probe" --launch login /tmp/agent-secret-settings-launch-probe/login.log
"$probe" --launch service /tmp/agent-secret-settings-launch-probe/service.log
```

The checked-in `SettingsLaunchTests` exercise actual synthesized
`NSAppleEventDescriptor` objects. Apple's
[default-launch documentation][default-launch] explains restoration and service
launches. The [launch-event constants][launch-events] describe login/service
origins; these values are read from `keyAEPropData`.

The pinned Sparkle installer relaunches its `applicationBundle`; Agent Secret
passes the nested updater helper as that bundle. There is no observed evidence
that Sparkle directly launched the old outer setup alert. The routing change
prevents incidental login/restoration launches from showing Settings while
preserving explicit opens.

## Fixture previews

Render the actual Settings window and details views without invoking production
services:

```sh
AGENT_SECRET_SETTINGS_PREVIEW_DIR=/tmp/agent-secret-settings-previews \
  mise exec -- swift test --package-path approver --filter SettingsWindowTests
```

The images use fixture CLI, version, and update states. They are offscreen
AppKit renders; inactive title-bar chrome is expected. They do not prove an
installation, registration, provider request, or signed update succeeded.

## Behavioral checks

```sh
mise exec -- swift test --package-path approver --filter Settings
```

These checks cover CLI links, missing or stale tools, bounded command output,
command timeout, launch intent, and diagnostics retaining the Settings window.
Opening Settings does not run diagnostics or contact a secret provider.
Installation uses normal `install-cli` conflict handling; it does not force an
overwrite. Background update bootstrap failures stay inline.

For the full repository lint gate, match CI's macOS integration-test setting:

```sh
AGENT_SECRET_TEST_MACOS_PEER_IDENTITY=1 mise run lint
mise run build
```

Without that opt-in, the unchanged daemon package's local coverage can fall below
its floor because its Mach message identity tests are skipped. These tests use
synthetic data and do not contact a secret provider.

[default-launch]: https://developer.apple.com/documentation/appkit/nsapplication/launchisdefaultuserinfokey
[launch-events]: https://developer.apple.com/documentation/coreservices/1556410-launch_apple_event_constants
