# Agent Secret Broker Instructions

This repository is intended to be a standalone open-source project. Keep it
independent from unrelated external projects.

## Boundaries

- Do not import or call code from unrelated external projects.
- Do not depend on external project Make targets, app code, infrastructure
  inventory, credentials, scripts, or runtime assumptions for product code,
  builds, or releases.
- Do not commit secret values, plaintext credentials, 1Password exports, or
  captured fixtures containing real values.
- Use example `op://` references only as inert documentation examples.
- Keep external project integration notes out of the core design unless
  they are clearly marked as generic consumer examples.

## Implementation Defaults

- Core CLI and broker: Go.
- macOS approval UI: Swift or SwiftUI/AppKit.
- Secret source: official 1Password SDK with desktop-app integration.
- First delivery mode: CLI-supervised `exec` with environment injection.
- Session storage: memory only.
- Audit format: JSONL metadata only.
- Socket directory: per-user private directory with mode `0700`.
- Native approver diagnostics: Apple Unified Logging with value-free messages.

## Commands

Use `mise` as the project toolchain entrypoint. Before local development:

```bash
mise run setup
```

Default checks:

```bash
mise run lint
mise run build
```

Focused checks:

```bash
mise run lint:go
mise exec -- golangci-lint run --timeout 5m
mise run lint:swift
mise run lint:secrets
mise run lint:smart
mise run test
scripts/lint.sh
scripts/lint-go.sh
```

Integration tests must be opt-in. Prefer environment variables that point at
test-only `op://` references, and never print fetched values.

## Test Policy

- Add fast unit tests before implementation.
- Use opt-in integration tests for 1Password SDK, macOS socket credentials, and
  native app foreground behavior.
- For external SDK or OS behavior, capture real sanitized fixtures or document
  the live smoke command that produced the observation.
- Tests may print hashes, lengths, metadata, or synthetic values. They must not
  print raw secrets.
- Help output and macOS app logs are product surfaces: test them for useful
  agent guidance and for absence of secret values before shipping.

## Documentation Policy

- Keep docs practical and implementation-focused.
- When creating or editing Markdown, run `mise run lint` or
  `npx --no-install markdownlint '**/*.md'` from a `mise exec` shell.
- Record research findings in docs before relying on them in implementation.
