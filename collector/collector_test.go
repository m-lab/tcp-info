package collector

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
)

type testCacheLogger struct{}

func (t *testCacheLogger) LogCacheStats(_, _ int) {}

func runTest(ctx context.Context) {
	// Open a server socket, connect to it, send data to it until the context is canceled.
	localAddr, err := net.ResolveTCPAddr("tcp", ":12345")
	rtx.Must(err, "No localhost")
	listener, err := net.ListenTCP("tcp", localAddr)
	rtx.Must(err, "Could not make TCP listener")
	hostname, err := os.Hostname()
	rtx.Must(err, "Could not run os.Hostname()")
	log.Println("Connection to", hostname)
	local, err := net.Dial("tcp", hostname+":12345")
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

func TestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A nice big buffer on the channel
	msgChan := make(chan []*inetdiag.ParsedMessage, 10000)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		Run(ctx, 0, msgChan, &testCacheLogger{})
		wg.Done()
	}()

	go func() {
		runTest(ctx)
		wg.Done()
	}()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.NewTimer(10 * time.Second).C:
			cancel()
			t.Error("It should not take 10 seconds to get enough messages. Something is wrong.")
			return
		}
	}()

	// Make sure we receive multiple different messages regarding port 12345
	count := 0
	var prev *inetdiag.ParsedMessage
	for msgs := range msgChan {
		changed := false
		for _, m := range msgs {
			if m == nil {
				continue
			}
			if m.InetDiagMsg != nil && m.InetDiagMsg.ID.SPort() == uint16(12345) {
				if prev == nil || prev.Compare(m) > inetdiag.NoMajorChange {
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
