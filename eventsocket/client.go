package eventsocket

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"strings"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
)

// Handler is the interface that all interested users of the event socket
// notifications should implement. It has two methods, one called on Open events
// and one called on Close events.
type Handler interface {
	Open(timestamp time.Time, uuid string, ID *inetdiag.SockID)
	Close(timestamp time.Time, uuid string)
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
			handler.Open(event.Timestamp, event.UUID, event.ID)
		case Close:
			handler.Close(event.Timestamp, event.UUID)
		default:
			log.Println("Unknown event type:", event.Event)
		}
	}

	// Reading on a closed socket doesn't give you an EOF error and the error it
	// does give you is unexported. The error it gives you should be treated the
	// same as EOF, because it corresponds to the connection terminating.
	// s.Err() consumes the EOF error, so it should also consume this one.
	// Because it doesn't, we do so here.
	err = s.Err()
	if strings.Contains(err.Error(), "use of closed network connection") {
		err = nil
	}
	rtx.Must(err, "Scanning of %f died with non-EOF error", socket)
}