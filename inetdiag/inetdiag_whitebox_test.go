package inetdiag

import (
	"syscall"
	"testing"

	"github.com/m-lab/go/rtx"
	"golang.org/x/sys/unix"
)

func TestProcessSingleMessageErrorPaths(t *testing.T) {
	var m syscall.NetlinkMessage
	m.Header.Seq = 1
	_, _, err := processSingleMessage(&m, 2, 0)
	if err != ErrBadSequence {
		t.Error("Should have had ErrBadSequence not", err)
	}
	m.Header.Pid = 2
	_, _, err = processSingleMessage(&m, 1, 3)
	if err != ErrBadPid {
		t.Error("Should have had ErrBadPid not", err)
	}
	m.Header.Type = unix.NLMSG_ERROR
	_, _, err = processSingleMessage(&m, 1, 2)
	if err != ErrBadMsgData {
		t.Error("Should have had ErrBadMsgData not", err)
	}
	m.Data = []byte{0, 0, 0, 0}
	_, ok, err := processSingleMessage(&m, 1, 2)
	rtx.Must(err, "A zero error should be fine")
	if ok {
		t.Error("Should not be ok is")
	}
	m.Data = []byte{0, 0, 0, 1}
	_, ok, err = processSingleMessage(&m, 1, 2)
	rtx.Must(err, "An error message should be fine")
	if ok {
		t.Error("Should not be ok but is")
	}
	m.Header.Flags |= unix.NLM_F_MULTI
	_, ok, err = processSingleMessage(&m, 1, 2)
	rtx.Must(err, "An error message should be fine")
	if !ok {
		t.Error("Should be ok but isn't")
	}
}
