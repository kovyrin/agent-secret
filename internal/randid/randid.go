package randid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func Generate(reader io.Reader, prefix string) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var data [16]byte
	if _, err := io.ReadFull(reader, data[:]); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(data[:]), nil
}
