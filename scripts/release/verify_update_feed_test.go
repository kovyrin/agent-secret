package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestSignedFeedBindsVersionNotesAndArchive(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dmg := []byte("synthetic DMG")
	archiveSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, dmg))
	xml := fmt.Sprintf(`<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>
<sparkle:version>1.0.35</sparkle:version><sparkle:shortVersionString>0.0.35</sparkle:shortVersionString>
<description><![CDATA[<p>release notes</p>]]></description>
<enclosure url="https://example.com/archive.dmg" length="%d" sparkle:edSignature="%s"/>
</item></channel></rss>`, len(dmg), archiveSignature)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(xml)))
	feed := fmt.Appendf([]byte(xml), "<!-- sparkle-signatures:\nedSignature: %s\nlength: %d\n-->\n", signature, len(xml))
	item, err := verifiedFeedItem(public, feed)
	if err != nil || item.Version != "1.0.35" || item.Short != "0.0.35" {
		t.Fatalf("signed candidate rejected: %v", err)
	}
	if err := item.verifyArchive(public, dmg, "https://example.com/archive.dmg"); err != nil {
		t.Fatalf("signed archive rejected: %v", err)
	}
	if err := item.verifyArchive(public, []byte("altered bytes"), "https://example.com/archive.dmg"); err == nil {
		t.Fatal("altered archive accepted")
	}
	feed = bytes.Replace(feed, []byte("release notes"), []byte("altered notes"), 1)
	if _, err := verifiedFeedItem(public, feed); err == nil {
		t.Fatal("altered embedded release notes accepted")
	}
}
