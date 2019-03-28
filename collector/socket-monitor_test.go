package collector_test

import (
	"io/ioutil"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/m-lab/tcp-info/collector"
)

func TestInetDiagReqV2Serialize(t *testing.T) {
	v2 := collector.NewInetDiagReqV2(syscall.AF_INET, 23, 0x0E)
	data := v2.Serialize()
	if v2.Len() != len(data) {
		t.Error(data, "should be length", v2.Len())
	}
}

func TestOneType(t *testing.T) {
	// Open an AF_LOCAL socket connection.
	// Get a safe name for the AF_LOCAL socket
	f, err := ioutil.TempFile("", "TestOneType")
	if err != nil {
		t.Error(err)
	}
	name := f.Name()
	os.Remove(name)

	// Open a listening UNIX socket at that mostly-safe name.
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Error(err)
	}
	defer l.Close()

	// Unblock all goroutines when the function exits.
	wg := sync.WaitGroup{}
	wg.Add(1)
	defer wg.Done()

	// Start a client connection in a goroutine.
	go func() {
		c, err := net.Dial("unix", name)
		if err != nil {
			t.Error(err)
		}
		c.Write([]byte("hi"))
		wg.Wait()
		c.Close()
	}()

	// Accept the client connection.
	fd, err := l.Accept()
	if err != nil {
		t.Error(err)
	}
	defer fd.Close()

	// Verify that OneType(AF_LOCAL) finds at least one connection.
	res, err := collector.OneType(syscall.AF_LOCAL)
	if err != nil {
		t.Error(err)
	}
	if len(res) == 0 {
		t.Error("We have at least one active stream open right now.")
	}
}
