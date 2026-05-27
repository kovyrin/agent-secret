package buildinfo

// Version is set by release and app-bundle builds with go build -ldflags -X.
//
//nolint:gochecknoglobals
var Version = "dev"

// Revision is set by app-bundle builds with go build -ldflags -X.
//
//nolint:gochecknoglobals
var Revision = ""

// GCPOAuthClientID is set by release and app-bundle builds when Agent Secret
// ships with a bundled Google Desktop OAuth client for GCP bootstrap auth.
//
//nolint:gochecknoglobals
var GCPOAuthClientID = ""

// GCPOAuthClientSecret is optional Desktop OAuth client material. Google treats
// installed-app clients as public, but keep this value out of logs and docs.
//
//nolint:gochecknoglobals
var GCPOAuthClientSecret = ""

func DisplayVersion() string {
	if Revision != "" {
		return "agent-secret " + Version + " (" + Revision + ")"
	}
	return "agent-secret " + Version
}
