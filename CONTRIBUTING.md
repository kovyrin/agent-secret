# Contributing

Agent Secret is not accepting broad external code contributions yet. The project
is still pre-1.0 and the trusted surface is intentionally narrow while the local
macOS release path settles.

Useful contributions at this stage:

- Bug reports with exact versions, commands, and non-secret logs.
- Documentation corrections that do not expand the support promise.
- Security reports through the private process in `SECURITY.md`.
- Reproduction notes for clean macOS install, upgrade, uninstall, or 1Password
  Desktop authorization behavior.

Please do not send drive-by feature PRs, platform ports, new secret backends,
session APIs, credential helpers, or installer integrations without prior
discussion. Those areas can change the security model and release scope.

## Development Setup

Use `mise` as the project toolchain entrypoint:

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
mise format
mise run lint:go
mise run lint:swift
mise run lint:shell
mise run lint:toml
mise run lint:secrets
mise run lint:vuln
mise run test
mise run test:race
mise run test:coverage
mise run test:smoke
```

Live 1Password integration tests are opt-in. Use test-only refs and never print
resolved values.

## Pull Request Expectations

If a PR is discussed and accepted before implementation:

- Keep the change focused.
- Update `CHANGELOG.md` for user-facing behavior, release-process changes, and
  security-relevant fixes.
- Update docs when support boundaries, commands, install behavior, or threat
  model assumptions change.
- Add fast unit tests before implementation when behavior changes.
- Do not commit raw secret values, real credential fixtures, private 1Password
  item metadata, or local signing material.

For Markdown changes, run:

```bash
npx --yes markdownlint-cli <path>
```
