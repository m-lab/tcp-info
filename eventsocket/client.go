package eventsocket

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
)

var (
	// Filename is a command-line flag holding the name of the unix-domain
	// socket that should be used by the client and server. It is put here in an
	// attempt to have just one standard flag name.
	Filename = flag.String("tcpinfo.eventsocket", "", "The filename of the unix-domain socket on which events are served.")
)

// Handler is the interface that all interested users of the event socket
// notifications should implement. It has two methods, one called on Open events
// and one called on Close events.
type Handler interface {
	Open(ctx context.Context, timestamp time.Time, uuid string, ID *inetdiag.SockID)
	Close(ctx context.Context, timestamp time.Time, uuid string, ID *inetdiag.SockID)
}

// MustRun will read from the passed-in socket filename until the context is
// cancelled. Any errors are fatal.
func MustRun(ctx context.Context, socket string, handler Handler) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c, err := net.Dial("unix", socket)
	rtx.Must(err, "Could not connect to %q", socket)
	go func() {
		// Close the connection when the context is done. Closing the underlying
		// connection means that the scanner will soon terminate.
		<-ctx.Done()
		c.Close()
	}()

	// By default bufio.Scanner is based on newlines, which is perfect for our JSONL protocol.
	s := bufio.NewScanner(c)
	for s.Scan() {
		var event FlowEvent
		rtx.Must(json.Unmarshal(s.Bytes(), &event), "Could not unmarshall")
		switch event.Event {
		case Open:
			handler.Open(ctx, event.Timestamp, event.UUID, event.ID)
		case Close:
			handler.Close(ctx, event.Timestamp, event.UUID, event.ID)
		default:
			log.Println("Unknown event type:", event.Event)
		}
	}

	// s.Err() is supposed to be nil under normal conditions. Scanner objects
	// hide the expected EOF error and return nil after they encounter it,
	// because EOF is the expected error. However, reading on a closed socket
	// doesn't give you an EOF error and the error it does give you is
	// unexported. The error it gives you should be treated the same as EOF,
	// because it corresponds to the connection terminating under normal
	// conditions. Because Scanner hides the EOF error, it should also hide the
	// unexported one. Because Scanner doesn't, we do so here. Other errors
	// should not be hidden.
	err = s.Err()
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		err = nil
	}
	rtx.Must(err, "Scanning of %f died with non-EOF error", socket)
}
