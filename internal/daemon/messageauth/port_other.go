//go:build !darwin

package messageauth

import (
	"errors"
	"time"
)

var (
	ErrTimeout       = errors.New("request attestation unavailable")
	ErrFrameMismatch = errors.New("request attestation unavailable")
)

type Identity struct {
	PID        int
	PIDVersion uint32
	UID        int
}

type Port struct{}

func NewPort() (*Port, error) { return nil, ErrTimeout }
func (*Port) Name() string    { return "" }
func (*Port) Close()          {}
func (*Port) Receive([]byte, time.Duration) (Identity, error) {
	return Identity{}, ErrTimeout
}
func Send(string, []byte) error { return ErrTimeout }
