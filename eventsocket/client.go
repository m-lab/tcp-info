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
	// Filename is a flag for the unix-domain socket on which events are served.
	Filename = flag.String("tcpinfo.eventsocket", "", "The filename of the unix-domain socket on which events are served.")

	// Bounds for the exponential backoff between (re)connection attempts.
	reconnectMinDelay = 100 * time.Millisecond
	reconnectMaxDelay = 10 * time.Second
)

// Handler is the interface that all users of the eventsocket client should
// implement.
type Handler interface {
	// Open is called when a new flow is created.
	Open(ctx context.Context, timestamp time.Time, uuid string, ID *inetdiag.SockID)
	// Close is called when a flow is closed.
	Close(ctx context.Context, timestamp time.Time, uuid string)
}

// MustRun connects to the given unix-domain socket and dispatches every
// received event to the handler until the context is canceled.
//
// The connection is maintained for the lifetime of the context: if the socket
// cannot be dialed, or an established connection is lost (for example because
// the server process restarted and created a new socket), MustRun waits with
// exponential backoff and connects again. Without this, a client would
// silently stop receiving events after a server restart. Events that occur
// while the client is disconnected are not delivered.
//
// It is still a "Must" function in the sense that it panics on events it
// cannot decode, which indicates a client/server version mismatch.
func MustRun(ctx context.Context, socket string, handler Handler) {
	delay := reconnectMinDelay
	for ctx.Err() == nil {
		connected, err := runConnection(ctx, socket, handler)
		if ctx.Err() != nil {
			return
		}
		if connected {
			// The last connection succeeded, so start over with a short delay.
			delay = reconnectMinDelay
		}
		if err != nil {
			log.Printf("Event socket %q: %v (retrying in %v)", socket, err, delay)
		} else {
			log.Printf("Event socket %q closed by server (reconnecting in %v)", socket, delay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > reconnectMaxDelay {
			delay = reconnectMaxDelay
		}
	}
}

// runConnection dials the socket and dispatches events until the connection
// is closed or the context is canceled. It returns whether the dial succeeded
// and the error that ended the connection, if any.
func runConnection(ctx context.Context, socket string, handler Handler) (bool, error) {
	c, err := net.Dial("unix", socket)
	if err != nil {
		return false, err
	}
	// Close the connection when the context is canceled, which unblocks the
	// scanner below. The per-connection context ensures the goroutine exits
	// when this function returns, not just when the parent is canceled.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		c.Close()
	}()

	s := bufio.NewScanner(c)
	for s.Scan() {
		var event FlowEvent
		rtx.Must(json.Unmarshal(s.Bytes(), &event), "Could not unmarshall")
		switch event.Event {
		case Open:
			handler.Open(ctx, event.Timestamp, event.UUID, event.ID)
		case Close:
			handler.Close(ctx, event.Timestamp, event.UUID)
		default:
			log.Println("Unknown event type:", event.Event)
		}
	}

	err = s.Err()
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		err = nil
	}
	return true, err
}
