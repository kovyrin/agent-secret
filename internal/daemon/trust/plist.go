package trust

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
)

func PlistString(path string, key string, errKind error) (string, error) {
	//nolint:gosec // G304: caller provides an Info.plist path under its own validated bundle root.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", errKind, path, err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var currentKey string
	for {
		tok, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", fmt.Errorf("%w: parse %s: %w", errKind, path, err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", fmt.Errorf("%w: parse %s key: %w", errKind, path, err)
			}
			currentKey = value
		case "string":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", fmt.Errorf("%w: parse %s string: %w", errKind, path, err)
			}
			if currentKey == key {
				return value, nil
			}
			currentKey = ""
		}
	}
	return "", fmt.Errorf("%w: %s missing %s", errKind, path, key)
}
