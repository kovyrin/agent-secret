// Command verify_update_feed validates the exact bytes of the stable Sparkle feed.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const signaturePrefix = "<!-- sparkle-signatures:\n"

var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$`)

type feedItem struct {
	Version     string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle version"`
	Short       string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle shortVersionString"`
	Description string `xml:"description"`
	NotesLink   string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle releaseNotesLink"`
	Archives    []struct {
		URL       string `xml:"url,attr"`
		Length    int    `xml:"length,attr"`
		Signature string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle edSignature,attr"`
	} `xml:"enclosure"`
}

func verifiedFeedItem(key ed25519.PublicKey, data []byte) (feedItem, error) {
	var result feedItem
	index := bytes.LastIndex(data, []byte(signaturePrefix))
	if index < 0 {
		return result, errors.New("feed signature is missing")
	}
	content, block := data[:index], data[index+len(signaturePrefix):]
	fields := strings.Split(strings.TrimSuffix(string(block), "\n"), "\n")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "edSignature: ") ||
		fields[1] != fmt.Sprintf("length: %d", len(content)) || fields[2] != "-->" {
		return result, errors.New("invalid feed signature block")
	}
	if !verifyBytes(key, content, strings.TrimPrefix(fields[0], "edSignature: ")) {
		return result, errors.New("feed signature does not verify")
	}
	var feed struct {
		XMLName xml.Name   `xml:"rss"`
		Items   []feedItem `xml:"channel>item"`
	}
	if err := xml.Unmarshal(content, &feed); err != nil || len(feed.Items) != 1 {
		return result, errors.New("stable feed must contain exactly one release")
	}
	result = feed.Items[0]
	version := releaseVersion.FindStringSubmatch(result.Short)
	if version == nil || version[1] == "9999" {
		return result, errors.New("invalid release version")
	}
	major, _ := strconv.Atoi(version[1])
	expectedBuild := fmt.Sprintf("%d.%s.%s", major+1, version[2], version[3])
	if result.Version != expectedBuild || len(result.Archives) != 1 || strings.TrimSpace(result.Description) == "" ||
		result.NotesLink != "" {
		return result, errors.New("feed does not bind one build, one archive, and embedded release notes")
	}
	return result, nil
}

func verifyBytes(key ed25519.PublicKey, data []byte, encoded string) bool {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && ed25519.Verify(key, data, signature)
}

func (item feedItem) verifyArchive(key ed25519.PublicKey, data []byte, url string) error {
	archive := item.Archives[0]
	if archive.URL != url || archive.Length != len(data) || !verifyBytes(key, data, archive.Signature) {
		return errors.New("archive URL, length, or signature does not match the signed appcast")
	}
	return nil
}

func run(args []string) error {
	if len(args) != 1 && len(args) != 3 {
		return errors.New("usage: verify_update_feed APPCAST [DMG DOWNLOAD_URL]")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("AGENT_SECRET_UPDATE_PUBLIC_KEY"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 update public key")
	}
	//nolint:gosec // Read the explicitly selected local feed and archive.
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	item, err := verifiedFeedItem(key, data)
	if err != nil {
		return err
	}
	if len(args) == 3 {
		//nolint:gosec // Read the explicitly selected local DMG.
		archive, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		if err := item.verifyArchive(key, archive, args[2]); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(os.Stdout, item.Short)
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "verify-update-feed: %v\n", err)
		os.Exit(1)
	}
}
