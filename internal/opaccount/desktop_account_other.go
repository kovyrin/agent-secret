//go:build !darwin || !cgo

package opaccount

func DetectDefaultDesktopAccount() string {
	return ""
}
