// example-eventsocket-client is a minimal reference implementation of a tcpinfo
// eventsocket client.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
)

var (
	mainCtx, mainCancel = context.WithCancel(context.Background())
)

// event contains fields for an open event.
type event struct {
	timestamp time.Time
	uuid      string
	id        *inetdiag.SockID
}

// handler implements the eventsocket.Handler interface.
type handler struct {
	events chan event
}

// Open is called by tcp-info synchronously for every TCP open event.
func (h *handler) Open(ctx context.Context, timestamp time.Time, uuid string, id *inetdiag.SockID) {
	// NOTE: Until this function returns, tcp-info cannot send additional
	// events. So, immediately attempt to send the event on a channel that will
	// be read by an asynchronous processing goroutine.
	select {
	case h.events <- event{timestamp: timestamp, uuid: uuid, id: id}:
		log.Println("open ", "sent", uuid, timestamp, id)
	default:
		// If the write to the events channel would have blocked, discard this
		// event instead.
		log.Println("open ", "skipped", uuid, timestamp, id)
	}
}

// Close is called by tcp-info synchronously for every TCP close event.
func (h *handler) Close(ctx context.Context, timestamp time.Time, uuid string) {
	log.Println("close", uuid, timestamp)
}

// ProcessOpenEvents reads and processes events received by the open handler.
func (h *handler) ProcessOpenEvents(ctx context.Context) {
	for {
		select {
		case e := <-h.events:
			log.Println("processing", e)
		case <-ctx.Done():
			log.Println("shutdown")
			return
		}
	}
}

func main() {
	defer mainCancel()

	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "could not get args from environment variables")

	if *eventsocket.Filename == "" {
		log.Fatal("-tcpinfo.eventsocket path is required")
	}

	h := &handler{events: make(chan event)}

	// Process events received by the eventsocket handler. The goroutine will
	// block until an open even occurs.
	go h.ProcessOpenEvents(mainCtx)

	// Begin listening on the eventsocket for new events, and dispatch them to
	// the given handler.
	go eventsocket.MustRun(mainCtx, *eventsocket.Filename, h)

	<-mainCtx.Done()
}
