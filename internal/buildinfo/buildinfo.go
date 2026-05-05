package buildinfo

// Version is set by release and app-bundle builds with go build -ldflags -X.
//
//nolint:gochecknoglobals
var Version = "dev"

func DisplayVersion() string {
	return "agent-secret " + Version
}
