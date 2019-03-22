package inetdiag_test

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/zstd"
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
	if hdr.ID.Interface() == 0 || hdr.ID.Cookie() == 0 || hdr.ID.DPort() == 0 || hdr.ID.String() == "" {
		t.Errorf("None of the accessed values should be zero")
	}
	if hdr.IDiagFamily != syscall.AF_INET {
		t.Errorf("Failed %+v\n", hdr)
	}
	if tcpinfo.TCPState(hdr.IDiagState) != tcpinfo.TCPState_SYN_RECV {
		t.Errorf("Failed %+v\n", hdr)
	}

	if len(value) != 28 {
		t.Error("Len", len(value))
	}

	hdr, value = inetdiag.ParseInetDiagMsg(data[:1])
	if hdr != nil || value != nil {
		t.Error("This should fail, the data is too small.")
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
		t.Errorf("Should be loopback but isn't")
	}
	if hdr.ID.DstIP().IsLoopback() {
		t.Errorf("Shouldn't be loopback but is")
	}
	if hdr.ID.SPort() != 0x3412 {
		t.Errorf("SPort should be 0x3412 %+v\n", hdr.ID)
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
	if mp.NLMsg.Header.Len != 356 {
		t.Error("wrong length")
	}
	if mp.InetDiagMsg.IDiagFamily != unix.AF_INET6 {
		t.Error("Should not be IPv6")
	}
	if len(mp.Attributes) != inetdiag.INET_DIAG_MAX {
		t.Error("Should be", inetdiag.INET_DIAG_MAX, "attribute entries")
	}
	if mp.InetDiagMsg.String() == "" {
		t.Error("Empty string made from InetDiagMsg")
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

	// TODO: verify that skiplocal actually skips a message when src or dst is 127.0.0.1
}

func TestParseGarbage(t *testing.T) {
	// Json encoding of a good netlink message containing inet diag info.
	var good = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(good), &nm)
	if err != nil {
		log.Fatal(err)
	}

	// Truncate the data down to something that makes no sense.
	badNm := nm
	badNm.Data = badNm.Data[:1]
	_, err = inetdiag.Parse(&badNm, true)
	if err == nil {
		t.Error("The parse should have failed")
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
	res, err := inetdiag.OneType(syscall.AF_LOCAL)
	if err != nil {
		t.Error(err)
	}
	if len(res) == 0 {
		t.Error("We have at least one active stream open right now.")
	}
}

func TestReader(t *testing.T) {
	// Cache info new 140  err 0 same 277 local 789 diff 3 total 1209
	// 1209 sockets 143 remotes 403 per iteration
	source := "testdata/testdata.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := 0
	for {
		_, err := inetdiag.LoadNext(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		parsed++
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}

func TestNLMsgSerialize(t *testing.T) {
	source := "testdata/testdata.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := 0
	for {
		msg, err := inetdiag.LoadNext(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		pm, err := inetdiag.Parse(msg, false)
		rtx.Must(err, "Could not parse test data")
		s := pm.Serialize()
		type OneLine struct {
			Timestamp   int64
			NLMsgHdr    syscall.NlMsghdr
			Attributes  []string
			InetDiagMsg inetdiag.InetDiagMsg
		}
		var o OneLine
		log.Println("JSON:", s)
		if strings.Contains(s, "\n") {
			t.Errorf("String %q should not have a newline in it", s)
		}
		rtx.Must(json.Unmarshal([]byte(s), &o), "Could not parse one line of output")
		log.Printf("%v\n", o)

		if o.Timestamp < 0 {
			// t.Errorf("Bad timestamp in %v (derived from %q)", o, s)  // FIXME: bad data in testdata
		}
		parsed++
	}
	if parsed != 420 {
		t.Error("Wrong count:", parsed)
	}
}

// TODO: add whitebox testing of socket-monitor to exercise error handling.
