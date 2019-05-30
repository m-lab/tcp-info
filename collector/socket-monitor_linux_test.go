package collector_test

import (
	"io/ioutil"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/collector"
	"github.com/m-lab/tcp-info/inetdiag"
	"golang.org/x/sys/unix"
)

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

func TestProcessSingleMessageErrorPaths(t *testing.T) {
	var m syscall.NetlinkMessage
	m.Header.Seq = 1
	_, _, err := collector.ProcessSingleMessage(&m, 2, 0)
	if err != inetdiag.ErrBadSequence {
		t.Error("Should have had ErrBadSequence not", err)
	}
	m.Header.Pid = 2
	_, _, err = collector.ProcessSingleMessage(&m, 1, 3)
	if err != inetdiag.ErrBadPid {
		t.Error("Should have had ErrBadPid not", err)
	}
	m.Header.Type = unix.NLMSG_ERROR
	_, _, err = collector.ProcessSingleMessage(&m, 1, 2)
	if err != inetdiag.ErrBadMsgData {
		t.Error("Should have had ErrBadMsgData not", err)
	}
	m.Data = []byte{0, 0, 0, 0}
	_, ok, err := collector.ProcessSingleMessage(&m, 1, 2)
	rtx.Must(err, "A zero error should be fine")
	if ok {
		t.Error("Should not be ok is")
	}
	m.Data = []byte{0, 0, 0, 1}
	_, ok, err = collector.ProcessSingleMessage(&m, 1, 2)
	rtx.Must(err, "An error message should be fine")
	if ok {
		t.Error("Should not be ok but is")
	}
	m.Header.Flags |= unix.NLM_F_MULTI
	_, ok, err = collector.ProcessSingleMessage(&m, 1, 2)
	rtx.Must(err, "An error message should be fine")
	if !ok {
		t.Error("Should be ok but isn't")
	}
}
