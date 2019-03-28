package collector

/*
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
import "C"
*/

import (
	"errors"
	"log"
	"syscall"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
	"github.com/m-lab/tcp-info/tcp"
)

// Constants from linux.
const (
	TCPDIAG_GETSOCK     = 18 // uapi/linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // uapi/linux/sock_diag.h
)

const TCPF_ALL = 0xFFF

var (
	// ErrBadPid is used when the PID is mismatched between the netlink socket and the calling process.
	ErrBadPid = errors.New("bad PID, can't listen to NL socket")

	// ErrBadSequence is used when the Netlink response has a bad sequence number.
	ErrBadSequence = errors.New("bad sequence number, can't interpret NetLink response")

	// ErrBadMsgData is used when the NHetlink response has bad or missing data.
	ErrBadMsgData = errors.New("bad message data from netlink message")
)

// InetDiagReqV2 is the Netlink request struct, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	ID            inetdiag.InetDiagSockID
}

// SizeofInetDiagReqV2 is the size of the struct.
// TODO should we just make this explicit in the code?
const SizeofInetDiagReqV2 = int(unsafe.Sizeof(InetDiagReqV2{})) // Should be 0x38

// Serialize is provided for json serialization?
// TODO - should use binary functions instead?
func (req *InetDiagReqV2) Serialize() []byte {
	return (*(*[SizeofInetDiagReqV2]byte)(unsafe.Pointer(req)))[:]
}

// Len is provided for json serialization?
func (req *InetDiagReqV2) Len() int {
	return SizeofInetDiagReqV2
}

// NewInetDiagReqV2 creates a new request.
func NewInetDiagReqV2(family, protocol uint8, states uint32) *InetDiagReqV2 {
	return &InetDiagReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		IDiagStates:   states,
	}
}

// TODO - Figure out why we aren't seeing INET_DIAG_DCTCPINFO or INET_DIAG_BBRINFO messages.
func makeReq(inetType uint8) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST)
	msg := NewInetDiagReqV2(inetType, syscall.IPPROTO_TCP,
		TCPF_ALL & ^((1<<uint(tcp.SYN_RECV))|(1<<uint(tcp.TIME_WAIT))|(1<<uint(tcp.CLOSE))))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_MEMINFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_INFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_VEGASINFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_CONG - 1))

	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_TCLASS - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_TOS - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_SKMEMINFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_SHUTDOWN - 1))

	req.AddData(msg)
	req.NlMsghdr.Type = SOCK_DIAG_BY_FAMILY
	req.NlMsghdr.Flags |= syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST
	return req
}

func processSingleMessage(m *syscall.NetlinkMessage, seq uint32, pid uint32) (*syscall.NetlinkMessage, bool, error) {
	if m.Header.Seq != seq {
		log.Printf("Wrong Seq nr %d, expected %d", m.Header.Seq, seq)
		metrics.ErrorCount.With(prometheus.Labels{"type": "wrong seq num"}).Inc()
		return nil, false, ErrBadSequence
	}
	if m.Header.Pid != pid {
		log.Printf("Wrong pid %d, expected %d", m.Header.Pid, pid)
		metrics.ErrorCount.With(prometheus.Labels{"type": "wrong pid"}).Inc()
		return nil, false, ErrBadPid
	}
	if m.Header.Type == unix.NLMSG_DONE {
		return nil, false, nil
	}
	if m.Header.Type == unix.NLMSG_ERROR {
		native := nl.NativeEndian()
		if len(m.Data) < 4 {
			return nil, false, ErrBadMsgData
		}
		error := int32(native.Uint32(m.Data[0:4]))
		if error == 0 {
			return nil, false, nil
		}
		log.Println(syscall.Errno(-error))
		metrics.ErrorCount.With(prometheus.Labels{"type": "NLMSG_ERROR"}).Inc()
	}
	if m.Header.Flags&unix.NLM_F_MULTI == 0 {
		return m, false, nil
	}
	return m, true, nil
}

// OneType handles the request and response for a single type, e.g. INET or INET6
// TODO maybe move this to top level?
func OneType(inetType uint8) ([]*syscall.NetlinkMessage, error) {
	var res []*syscall.NetlinkMessage

	start := time.Now()
	defer func() {
		af := "unknown"
		switch inetType {
		case syscall.AF_INET:
			af = "ipv4"
		case syscall.AF_INET6:
			af = "ipv6"
		}
		metrics.SyscallTimeHistogram.With(prometheus.Labels{"af": af}).Observe(time.Since(start).Seconds())
		metrics.ConnectionCountHistogram.With(prometheus.Labels{"af": af}).Observe(float64(len(res)))
	}()

	req := makeReq(inetType)

	// Copied this from req.Execute in nl_linux.go
	sockType := syscall.NETLINK_INET_DIAG
	s, err := nl.Subscribe(sockType)
	if err != nil {
		// TODO - all these logs should be metrics instead.
		log.Println(err)
		return nil, err
	}
	defer s.Close()

	if err := s.Send(req); err != nil {
		log.Println(err)
		return nil, err
	}

	pid, err := s.GetPid()
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Adapted this from req.Execute in nl_linux.go
	for {
		msgs, err := s.Receive()
		if err != nil {
			log.Println(err)
			return nil, err
		}
		// TODO avoid the copy.
		for i := range msgs {
			m, shouldContinue, err := processSingleMessage(&msgs[i], req.Seq, pid)
			if err != nil {
				return res, err
			}
			if m != nil {
				res = append(res, m)
			}
			if !shouldContinue {
				return res, nil
			}
			//	if resType != 0 && m.Header.Type != resType {
			//		continue
			//	}
		}
	}
}
