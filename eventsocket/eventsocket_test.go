package eventsocket

import (
	"bufio"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/go-test/deep"

	"github.com/m-lab/go/rtx"
)

func TestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "TestEventSocketServer")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	srv := New(dir + "/tcpevents.sock")
	srv.Listen()
	go srv.Serve(ctx)
	log.Println("About to dial")
	c, err := net.Dial("unix", dir+"/tcpevents.sock")
	rtx.Must(err, "Could not open UNIX domain socket")

	// Busy wait until the server has registered the client
	for {
		srv.mutex.Lock()
		length := len(srv.clients)
		srv.mutex.Unlock()
		if length > 0 {
			break
		}
	}

	// Send an event on the server, to cause the client to be notified by the server.
	srv.FlowDeleted("fakeuuid")
	r := bufio.NewScanner(c)
	if !r.Scan() {
		t.Error("Should have been able to scan until the next newline, but couldn't")
	}
	var event FlowEvent
	rtx.Must(json.Unmarshal(r.Bytes(), &event), "Could not unmarshall")
	if event.Event != Close || event.UUID != "fakeuuid" {
		t.Error("Event was supposed to be {Close, 'fakeuuid'}, not", event)
	}

	// Send another event on the server, to cause the client to be notified by the server.
	before := time.Now()
	srv.FlowCreated("src", "dst", 1, 2, "fakeuuid2")
	if !r.Scan() {
		t.Error("Should have been able to scan until the next newline, but couldn't")
	}
	rtx.Must(json.Unmarshal(r.Bytes(), &event), "Could not unmarshall")
	after := time.Now()
	if before.After(event.Timestamp) || after.Before(event.Timestamp) {
		t.Error("It should be true that", before, "<", event.Timestamp, "<", after)
	}
	event.Timestamp = time.Time{}
	if diff := deep.Equal(event, FlowEvent{Open, time.Time{}, "src", "dst", 1, 2, "fakeuuid2"}); diff != nil {
		t.Error("Event differed from expected:", diff)
	}

	// Close down things the client. When the server next tries to send
	// something to the client, the client should get removed from the set of
	// active clients.
	c.Close()

	// Now verify some internal error handling:
	srv.eventC <- nil
	srv.removeClient(nil)
	// No SIGSEGV == success!

	// Send an event to ensure that cleanup should occur.
	srv.FlowDeleted("fakeuuid")

	// Busy wait until the server has unregistered the client
	for {
		srv.mutex.Lock()
		length := len(srv.clients)
		srv.mutex.Unlock()
		if length == 0 {
			break
		}
	}
	// Cancel the context to shutdown the server.
	cancel()
	// Wait for every component goroutine of the server to complete.
	srv.servingWG.Wait()
	// No timeout == success!
}

func TestTCPEvent_String(t *testing.T) {
	tests := []struct {
		want string
		i    TCPEvent
	}{
		{"Open", Open},
		{"Close", Close},
		{"TCPEvent(3)", TCPEvent(3)},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.i.String(); got != tt.want {
				t.Errorf("TCPEvent.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
