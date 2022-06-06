package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
)

var (
	mainCtx, mainCancel = context.WithCancel(context.Background())
)

type event struct {
	timestamp time.Time
	uuid      string
	id        *inetdiag.SockID
}

type handler struct {
	events chan event
}

// Open is called single-threaded and blocking for every TCP open event.
func (h *handler) Open(ctx context.Context, timestamp time.Time, uuid string, id *inetdiag.SockID) {
	log.Println("open ", uuid, timestamp, id)
	h.events <- event{timestamp: timestamp, uuid: uuid, id: id}
}

// Close is called single-threaded and blocking for every TCP close event.
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
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from environment variables")
	defer mainCancel()

	if *eventsocket.Filename == "" {
		panic("-tcpinfo.eventsocket path is required")
	}

	wg := sync.WaitGroup{}
	h := &handler{events: make(chan event)}

	wg.Add(1)
	go func() {
		h.ProcessOpenEvents(mainCtx)
		wg.Done()
	}()

	// Listen to the event socket to find out about new UUIDs and then process them.
	wg.Add(1)
	go func() {
		eventsocket.MustRun(mainCtx, *eventsocket.Filename, h)
		wg.Done()
	}()

	wg.Wait()
	fmt.Println("ok")
}
