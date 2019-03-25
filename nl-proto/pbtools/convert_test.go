package pbtools_test

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"syscall"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/m-lab/tcp-info/inetdiag"
	tcpinfo "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/nl-proto/pbtools"
	"github.com/m-lab/tcp-info/zstd"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// Package error messages
var (
	ErrInetDiagParseFailed = errors.New("Error parsing inetdiag message")
	ErrLocal               = errors.New("Connection is loopback")
	ErrUnknownMessageType  = errors.New("Unknown netlink message type")
)

func convertToProto(msg *syscall.NetlinkMessage, t *testing.T) *tcpinfo.TCPDiagnosticsProto {
	parsedMsg, err := inetdiag.Parse(msg, true)
	if err != nil {
		t.Fatal(err)
	}
	return pbtools.CreateProto(time.Now(), msg.Header, parsedMsg.InetDiagMsg, parsedMsg.Attributes[:])
}

func TestReader(t *testing.T) {
	source := "testdata/testdata.zst"
	log.Println("Reading messages from", source)
	rdr := zstd.NewReader(source)
	parsed := 0
	src4 := 0
	dst4 := 0
	for {
		msg, err := inetdiag.LoadNext(rdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}

		p := convertToProto(msg, t)
		if p.InetDiagMsg == nil {
			t.Fatal("InetDiagMsg missing")
		}
		if p.CongestionAlgorithm != "cubic" {
			t.Error(p.CongestionAlgorithm, []byte(p.CongestionAlgorithm))
		}
		if p.MemInfo == nil {
			t.Error("MemInfo missing")
		}
		if p.TcpInfo == nil {
			t.Fatal("TcpInfo missing")
		}
		if p.TcpInfo.State != p.InetDiagMsg.State {
			t.Fatal("State mismatch")
		}
		if len(p.InetDiagMsg.SockId.Source.Ip) == 4 {
			src4++
		}
		if len(p.InetDiagMsg.SockId.Destination.Ip) == 4 {
			dst4++
		}

		parsed++
	}

	if src4 == 0 {
		t.Error("There should be some ipv4 sources")
	}
	if dst4 == 0 {
		t.Error("There should be some ipv4 destinations")
	}
	// TODO - do some test on the proto	}
	if parsed != 420 { // 140 new, 277 same, and 3 diff
		t.Error(parsed)
	}
}

func TestCompare(t *testing.T) {
	var json1 = `{"Header":{"Len":356,"Type":20,"Flags":2,"Seq":1,"Pid":148940},"Data":"CgEAAOpWE6cmIAAAEAMEFbM+nWqBv4ehJgf4sEANDAoAAAAAAAAAgQAAAAAdWwAAAAAAAAAAAAAAAAAAAAAAAAAAAAC13zIBBQAIAAAAAAAFAAUAIAAAAAUABgAgAAAAFAABAAAAAAAAAAAAAAAAAAAAAAAoAAcAAAAAAICiBQAAAAAAALQAAAAAAAAAAAAAAAAAAAAAAAAAAAAArAACAAEAAAAAB3gBQIoDAECcAABEBQAAuAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUCEAAAAAAAAgIQAAQCEAANwFAACsywIAJW8AAIRKAAD///9/CgAAAJQFAAADAAAALMkAAIBwAAAAAAAALnUOAAAAAAD///////////ayBAAAAAAASfQPAAAAAADMEQAANRMAAAAAAABiNQAAxAsAAGMIAABX5AUAAAAAAAoABABjdWJpYwAAAA=="}`
	nm := syscall.NetlinkMessage{}
	err := json.Unmarshal([]byte(json1), &nm)
	if err != nil {
		log.Fatal(err)
	}
	mp1, err := inetdiag.Parse(&nm, true)
	if err != nil {
		log.Fatal(err)
	}

	// Another independent copy.
	nm2 := syscall.NetlinkMessage{}
	err = json.Unmarshal([]byte(json1), &nm2)
	if err != nil {
		log.Fatal(err)
	}
	mp2, err := inetdiag.Parse(&nm2, true)
	if err != nil {
		log.Fatal(err)
	}

	// INET_DIAG_INFO Last... fields should be ignored
	for i := int(pbtools.LastDataSentOffset); i < int(pbtools.PmtuOffset); i++ {
		mp2.Attributes[inetdiag.INET_DIAG_INFO].Value[i] += 1
	}
	diff := pbtools.Compare(mp1, mp2)
	if diff != pbtools.NoMajorChange {
		t.Error("Last field changes should not be detected:", deep.Equal(mp1.Attributes[inetdiag.INET_DIAG_INFO],
			mp2.Attributes[inetdiag.INET_DIAG_INFO]))
	}

	// Early parts of INET_DIAG_INFO Should be ignored
	mp2.Attributes[inetdiag.INET_DIAG_INFO].Value[10] = 7
	diff = pbtools.Compare(mp1, mp2)
	if diff != pbtools.StateOrCounterChange {
		t.Error("Early field change not detected:", deep.Equal(mp1.Attributes[inetdiag.INET_DIAG_INFO],
			mp2.Attributes[inetdiag.INET_DIAG_INFO]))
	}

	// packet, segment, and byte counts should NOT be ignored
	mp2.Attributes[inetdiag.INET_DIAG_INFO].Value[pbtools.PmtuOffset] = 123
	diff = pbtools.Compare(mp1, mp2)
	if diff != pbtools.StateOrCounterChange {
		t.Error("Late field change not detected:", deep.Equal(mp1.Attributes[inetdiag.INET_DIAG_INFO],
			mp2.Attributes[inetdiag.INET_DIAG_INFO]))
	}
}
