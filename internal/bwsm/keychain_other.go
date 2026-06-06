//go:build !darwin || !cgo

package bwsm

import "context"

func keychainGet(context.Context, string, string) ([]byte, error) {
	return nil, ErrUnsupportedStore
}

func keychainPut(context.Context, string, string, []byte) error {
	return ErrUnsupportedStore
}

func keychainPutAllowingUserInteraction(context.Context, string, string, []byte) error {
	return ErrUnsupportedStore
}

func keychainDelete(context.Context, string, string) (bool, error) {
	return false, ErrUnsupportedStore
}
