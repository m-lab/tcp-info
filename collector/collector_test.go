package collector

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func testFatal(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

type testCacheLogger struct{}

func (t *testCacheLogger) LogCacheStats(_, _ int) {}

func runTest(ctx context.Context, port int) {
	// Open a server socket, connect to it, send data to it until the context is canceled.
	address := fmt.Sprintf("localhost:%d", port)
	log.Println("Listening on", address)
	localAddr, err := net.ResolveTCPAddr("tcp", address)
	rtx.Must(err, "No localhost")
	listener, err := net.ListenTCP("tcp", localAddr)
	rtx.Must(err, "Could not make TCP listener")
	local, err := net.Dial("tcp", address)
	defer local.Close()
	rtx.Must(err, "Could not connect to myself")
	conn, err := listener.AcceptTCP()
	rtx.Must(err, "Could not accept conn")
	go func() {
		for ctx.Err() == nil {
			conn.Write([]byte("hello"))
		}
	}()
	buff := make([]byte, 1024)
	for ctx.Err() == nil {
		local.Read(buff)
	}
}

func findPort() int {
	portFinder, err := net.Listen("tcp", ":0")
	rtx.Must(err, "Could not open server to discover open ports")
	port := portFinder.Addr().(*net.TCPAddr).Port
	portFinder.Close()
	return port
}

func TestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := findPort()

	// A nice big buffer on the channel
	msgChan := make(chan []*inetdiag.ParsedMessage, 10000)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		Run(ctx, 0, msgChan, &testCacheLogger{}, false)
		wg.Done()
	}()

	go func() {
		runTest(ctx, port)
		wg.Done()
	}()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.NewTimer(10 * time.Second).C:
			cancel()
			close(msgChan)
			t.Error("It should not take 10 seconds to get enough messages. Something is wrong.")
			return
		}
	}()

	// Make sure we receive multiple different messages regarding the open port
	count := 0
	var prev *inetdiag.ParsedMessage
	for msgs := range msgChan {
		changed := false
		for _, m := range msgs {
			if m == nil {
				continue
			}
			idm, err := m.RawIDM.Parse()
			testFatal(t, err)
			if idm != nil && idm.ID.SPort() == uint16(port) {
				change, err := m.Compare(prev)
				if err != nil {
					log.Println(err)
				} else if change > inetdiag.NoMajorChange {
					prev = m
					changed = true
				}
			}
		}
		if changed {
			count++
		}
		if count > 10 {
			cancel()
			break
		}
	}

	log.Println("Waiting for goroutines to exit")
	wg.Wait()
}
