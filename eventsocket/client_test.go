package eventsocket

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
)

type testHandler struct {
	opens, closes int
	wg            sync.WaitGroup
}

func (t *testHandler) Open(timestamp time.Time, uuid string, id *inetdiag.SockID) {
	t.opens++
	t.wg.Done()
}

func (t *testHandler) Close(timestamp time.Time, uuid string) {
	t.closes++
	t.wg.Done()
}

func TestClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "TestEventSocketClient")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	srv := New(dir + "/tcpevents.sock").(*server)
	srv.Listen()
	srvCtx, srvCancel := context.WithCancel(context.Background())
	go srv.Serve(srvCtx)
	defer srvCancel()

	th := &testHandler{}
	clientWg := sync.WaitGroup{}
	clientWg.Add(1)
	go func() {
		MustRun(ctx, dir+"/tcpevents.sock", th)
		clientWg.Done()
	}()
	th.wg.Add(2)

	// Send an open event
	srv.FlowCreated(time.Now(), "fakeuuid", inetdiag.SockID{})
	// Send a bad event and make sure nothing crashes.
	srv.eventC <- &FlowEvent{
		Event:     TCPEvent(1000),
		Timestamp: time.Now(),
		UUID:      "fakeuuid",
	}
	// Send a deletion event
	srv.FlowDeleted(time.Now(), "fakeuuid")
	th.wg.Wait() // Wait until the handler gets two events!

	// Cancel the context and wait until the client stops running.
	cancel()
	clientWg.Wait()
}
