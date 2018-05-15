package inetdiag_test

import (
	"encoding/json"
	"log"
	"syscall"
	"testing"
	"unsafe"

	"github.com/m-lab/tcp-info/inetdiag"
	"golang.org/x/sys/unix"

	tcpinfo "github.com/m-lab/tcp-info/nl-proto"
)

// This is not exhaustive, but covers the basics.  Integration tests will expose any more subtle
// problems.

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestSizes(t *testing.T) {
	if unsafe.Sizeof(inetdiag.InetDiagSockID{}) != 48 {
		t.Error("SockID wrong size", unsafe.Sizeof(inetdiag.InetDiagSockID{}))
	}

	hdr := inetdiag.InetDiagMsg{}
	if unsafe.Sizeof(hdr) != 4*6+unsafe.Sizeof(inetdiag.InetDiagSockID{}) {
		t.Error("Header is wrong size", unsafe.Sizeof(hdr))
	}
}

func TestParseInetDiagMsg(t *testing.T) {
	var data [100]byte
	for i := range data {
		data[i] = byte(i + 2)
	}
	hdr, value := inetdiag.ParseInetDiagMsg(data[:])
	if hdr.IDiagFamily != syscall.AF_INET {
		t.Errorf("Failed %+v\n", hdr)
	}
	if tcpinfo.TCPState(hdr.IDiagState) != tcpinfo.TCPState_SYN_RECV {
		t.Errorf("Failed %+v\n", hdr)
	}

	if len(value) != 28 {
		t.Error("Len", len(value))
	}
}

func TestSerialize(t *testing.T) {
	v2 := inetdiag.NewInetDiagReqV2(syscall.AF_INET, 23, 0x0E)
	data := v2.Serialize()
	if v2.Len() != len(data) {
		t.Error(data, "should be length", v2.Len())
	}
}

func TestID4(t *testing.T) {
	var data [unsafe.Sizeof(inetdiag.InetDiagMsg{})]byte
	srcIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSrc)
	data[srcIPOffset] = 127
	data[srcIPOffset+1] = 0
	data[srcIPOffset+2] = 0
	data[srcIPOffset+3] = 1

	srcPortOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSPort)
	// netlink uses host byte ordering, which may or may not be network byte ordering.  So no swapping should be
	// done.
	*(*uint16)(unsafe.Pointer(&data[srcPortOffset])) = 0x1234

	dstIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDst)
	data[dstIPOffset] = 1
	data[dstIPOffset+1] = 0
	data[dstIPOffset+2] = 0
	data[dstIPOffset+3] = 127 // Looks like localhost, but its reversed.

	hdr, _ := inetdiag.ParseInetDiagMsg(data[:])
	if !hdr.ID.SrcIP().IsLoopback() {
		log.Println(hdr.ID.SrcIP().IsLoopback())
	}
	if hdr.ID.IDiagSPort != 0x1234 {
		t.Errorf("SPort should be 0x1234 %+v\n", hdr.ID)
	}

	if !hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback") // Yeah I know this is not self-consistent. :P
	}
}

func TestID6(t *testing.T) {
	var data [unsafe.Sizeof(inetdiag.InetDiagMsg{})]byte
	srcIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagSrc)
	for i := 0; i < 8; i++ {
		data[srcIPOffset] = byte(0x0A + i)
	}

	dstIPOffset := unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID) + unsafe.Offsetof(inetdiag.InetDiagMsg{}.ID.IDiagDst)
	for i := 0; i < 8; i++ {
		data[dstIPOffset] = byte(i + 1)
	}

	hdr, _ := inetdiag.ParseInetDiagMsg(data[:])

	if hdr.ID.SrcIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Should not be identified as loopback")
	}
}

func TestParse(t *testing.T) {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		log.Fatal(err)
	}
	mp, err := inetdiag.Parse(&nm, true)
	if err != nil {
		log.Fatal(err)
	}
	if mp.Header.Len != 356 {
		t.Error("wrong length")
	}
	if mp.InetDiagMsg.IDiagFamily != unix.AF_INET6 {
		t.Error("Should not be IPv6")
	}
	if len(mp.Attributes) != inetdiag.INET_DIAG_MAX {
		t.Error("Should be", inetdiag.INET_DIAG_MAX, "attribute entries")
	}

	nonNil := 0
	for i := range mp.Attributes {
		if mp.Attributes[i] != nil {
			nonNil++
		}
	}
	if nonNil != 7 {
		t.Error("Incorrect number of attribs")
	}

	if mp.Attributes[inetdiag.INET_DIAG_INFO] == nil {
		t.Error("Should not be nil")
	}
}

func TestParseGarbage(t *testing.T) {
	// Json encoding of a good netlink message containing inet diag info.
	var good = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(good), &nm)
	if err != nil {
		log.Fatal(err)
	}
	// Replace the header type with one that we don't support.
	nm.Header.Type = 10
	_, err = inetdiag.Parse(&nm, false)
	if err == nil {
		t.Error("Should detect wrong type")
	}

	// Restore the header type.
	nm.Header.Type = 20
	// Replace the payload with garbage.
	for i := range nm.Data {
		// Replace the attribute records with garbage
		nm.Data[i] = byte(i)
	}

	_, err = inetdiag.Parse(&nm, false)
	if err == nil || err.Error() != "invalid argument" {
		t.Error(err)
	}

	// Replace length with garbage so that data is incomplete.
	nm.Header.Len = 400
	_, err = inetdiag.Parse(&nm, false)
	if err == nil || err.Error() != "invalid argument" {
		t.Error(err)
	}
}
