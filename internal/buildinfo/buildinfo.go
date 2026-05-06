package buildinfo

// Version is set by release and app-bundle builds with go build -ldflags -X.
//
//nolint:gochecknoglobals
var Version = "dev"

// Revision is set by app-bundle builds with go build -ldflags -X.
//
//nolint:gochecknoglobals
var Revision = ""

func DisplayVersion() string {
	if Revision != "" {
		return "agent-secret " + Version + " (" + Revision + ")"
	}
	return "agent-secret " + Version
}
