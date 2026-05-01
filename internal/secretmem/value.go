package secretmem

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

var ErrDestroyed = errors.New("secret memory value destroyed")

type Value struct {
	data   []byte
	length int
}

func New(value string) (*Value, error) {
	size := len(value)
	if size == 0 {
		size = 1
	}

	data, err := unix.Mmap(
		-1,
		0,
		size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if err != nil {
		return nil, fmt.Errorf("allocate locked secret memory: %w", err)
	}

	if err := unix.Mlock(data); err != nil {
		zero(data)
		_ = unix.Munmap(data)
		return nil, fmt.Errorf("lock secret memory: %w", err)
	}

	copy(data, value)
	return &Value{data: data, length: len(value)}, nil
}

func (v *Value) String() (string, error) {
	if v == nil || v.data == nil {
		return "", ErrDestroyed
	}
	return string(v.data[:v.length]), nil
}

func (v *Value) Destroy() error {
	if v == nil || v.data == nil {
		return nil
	}

	data := v.data
	v.data = nil
	v.length = 0

	zero(data)
	unlockErr := unix.Munlock(data)
	unmapErr := unix.Munmap(data)
	if unlockErr != nil {
		return fmt.Errorf("unlock secret memory: %w", unlockErr)
	}
	if unmapErr != nil {
		return fmt.Errorf("release secret memory: %w", unmapErr)
	}
	return nil
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}
