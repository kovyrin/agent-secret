# Dependency Notes

Status: current runtime dependency exceptions.

## 1Password SDK Fork

Agent Secret currently depends on
`github.com/kovyrin/onepassword-sdk-go` instead of the upstream
`github.com/1password/onepassword-sdk-go` module.

This is a temporary fork used for the macOS desktop integration path. It keeps
Agent Secret on the official SDK codebase while carrying the minimum changes we
need before upstream accepts them:

- stable desktop integration behavior for long-lived daemon processes;
- item metadata APIs required by `agent-secret item describe`;
- resolver behavior that lets one daemon process use multiple 1Password
  accounts without poisoning later requests.

The fork is not an alternate secret source and must not grow Agent Secret
specific product behavior. Product code still imports the SDK only through
`internal/opresolver`, and all live SDK tests remain opt-in.

Removal criteria:

- the upstream SDK exposes the item metadata APIs Agent Secret uses;
- the upstream desktop integration client remains valid for the resolver
  lifetime needed by a long-lived daemon;
- multi-account resolver tests pass against the upstream module.

When those criteria are met, replace the module path in `go.mod`, run
`go mod tidy`, run the full Go test suite, and remove this exception note.
