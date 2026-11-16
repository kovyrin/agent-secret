package buildinfo

// Version is set by release and app-bundle builds with go build -ldflags -X.
//
//nolint:gochecknoglobals
var Version = "dev"

// BundleVersion identifies the release build embedded in packaged executables.
//
//nolint:gochecknoglobals // Set by go build -ldflags -X.
var BundleVersion = ""

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
