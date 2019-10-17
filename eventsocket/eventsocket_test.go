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
		length := len(srv.listeners)
		srv.mutex.Unlock()
		if length > 0 {
			break
		}
	}

	// Send an event
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

	// Send another event
	srv.FlowCreated("src", "dst", 1, 2, "fakeuuid2")
	if !r.Scan() {
		t.Error("Should have been able to scan until the next newline, but couldn't")
	}
	rtx.Must(json.Unmarshal(r.Bytes(), &event), "Could not unmarshall")
	if diff := deep.Equal(event, FlowEvent{Open, "src", "dst", 1, 2, "fakeuuid2"}); diff != nil {
		t.Error("Event differed from expected:", diff)
	}

	c.Close()

	// Now verify some internal error handling:
	srv.eventC <- nil
	srv.removeListener(nil)
	// No SIGSEGV == success!

	// Send an event
	srv.FlowDeleted("fakeuuid")

	// Busy wait until the server has unregistered the client
	for {
		srv.mutex.Lock()
		length := len(srv.listeners)
		srv.mutex.Unlock()
		if length == 0 {
			break
		}
	}
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
