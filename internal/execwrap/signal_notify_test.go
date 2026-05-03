package execwrap

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestSignalNotifyRegistersSignalChannel(t *testing.T) {
	ch := make(chan os.Signal, 1)
	signalNotify(ch, syscall.SIGUSR1)
	t.Cleanup(func() { signal.Stop(ch) })

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("send signal: %v", err)
	}
	select {
	case got := <-ch:
		if got != syscall.SIGUSR1 {
			t.Fatalf("signal = %v, want SIGUSR1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SIGUSR1")
	}
}
