package execwrap

import (
	"os"
	"os/signal"
)

func signalNotify(ch chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(ch, sig...)
}
