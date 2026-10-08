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

func (t *testHandler) Open(ctx context.Context, timestamp time.Time, uuid string, id *inetdiag.SockID) {
	t.opens++
	t.wg.Done()
}

func (t *testHandler) Close(ctx context.Context, timestamp time.Time, uuid string) {
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
	// Events sent before the client is connected are dropped by the server,
	// so wait for the connection before sending anything.
	waitForClients(t, srv, 1)
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

// waitForClients blocks until the server has the given number of connected
// clients, or fails the test after a timeout.
func waitForClients(t *testing.T, srv *server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mutex.Lock()
		count := len(srv.clients)
		srv.mutex.Unlock()
		if count == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server never reached %d connected clients", n)
}

func TestClientReconnectsAfterServerRestart(t *testing.T) {
	reconnectMinDelay = 10 * time.Millisecond
	reconnectMaxDelay = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "TestEventSocketClientReconnect")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)
	sock := dir + "/tcpevents.sock"

	// Start the client before any server exists: the dial must be retried.
	th := &testHandler{}
	clientWg := sync.WaitGroup{}
	clientWg.Add(1)
	go func() {
		MustRun(ctx, sock, th)
		clientWg.Done()
	}()

	// First server.
	srv1 := New(sock).(*server)
	rtx.Must(srv1.Listen(), "Could not listen")
	srv1Ctx, srv1Cancel := context.WithCancel(context.Background())
	go srv1.Serve(srv1Ctx)
	waitForClients(t, srv1, 1)

	th.wg.Add(1)
	srv1.FlowCreated(time.Now(), "uuid1", inetdiag.SockID{})
	th.wg.Wait()

	// Simulate a server restart: tear down the first server, including its
	// accepted connections (which a dying process would close), then bring up
	// a new server on the same socket path.
	srv1Cancel()
	srv1.mutex.Lock()
	for c := range srv1.clients {
		c.Close()
	}
	srv1.mutex.Unlock()
	srv1.servingWG.Wait()

	srv2 := New(sock).(*server)
	rtx.Must(srv2.Listen(), "Could not listen")
	srv2Ctx, srv2Cancel := context.WithCancel(context.Background())
	defer srv2Cancel()
	go srv2.Serve(srv2Ctx)

	// The client must reconnect on its own and receive events from the new
	// server.
	waitForClients(t, srv2, 1)
	th.wg.Add(1)
	srv2.FlowCreated(time.Now(), "uuid2", inetdiag.SockID{})
	th.wg.Wait()

	if th.opens != 2 {
		t.Errorf("expected 2 open events across both servers, got %d", th.opens)
	}

	cancel()
	clientWg.Wait()
}
