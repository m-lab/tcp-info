package other

/*
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
*/
import "C"

import (
	"io"
	"log"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/m-lab/tcp-info/other/api"

	//	"github.com/gogo/protobuf/proto"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var OutBuf io.Writer

const TCPF_ALL = 0xFFF

//
// // linux/sock_diag.h
// const SOCK_DIAG_BY_FAMILY = 20
//
// const (
// 	_ = iota
// 	TCP_ESTABLISHED
// 	TCP_SYN_SENT
// 	TCP_SYN_RECV
// 	TCP_FIN_WAIT1
// 	TCP_FIN_WAIT2
// 	TCP_TIME_WAIT
// 	TCP_CLOSE
// 	TCP_CLOSE_WAIT
// 	TCP_LAST_ACK
// 	TCP_LISTEN
// 	TCP_CLOSING
// )
//

// ParseRouteAttr is adapted from vishvananda/netlink/nl
// TODO - reduce allocations.
func ParseRouteAttr(b []byte, attrs []syscall.NetlinkRouteAttr) ([]syscall.NetlinkRouteAttr, error) {
	//attrs := make([]syscall.NetlinkRouteAttr, 0, 8) // 8 or 10 seems best for now.
	for len(b) >= unix.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: syscall.RtAttr(*a), Value: vbuf[:int(a.Len)-unix.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

func OneType(inet_type uint8) []syscall.NetlinkMessage {
	req := nl.NewNetlinkRequest(SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP)
	{
		// TODO - need to do AF_INET6 as well
		msg := NewInetDiagReqV2(inet_type, syscall.IPPROTO_TCP,
			TCPF_ALL & ^((1<<TCP_SYN_RECV)|(1<<TCP_TIME_WAIT)|(1<<TCP_CLOSE)))
		// msg := InetDiagReqV2{
		// 	sdiag_family:   syscall.AF_INET,
		// 	sdiag_protocol: syscall.IPPROTO_TCP,
		// 	idiag_states:   TCPF_ALL & ^((1 << TCP_SYN_RECV) | (1 << TCP_TIME_WAIT) | (1 << TCP_CLOSE)),
		// }
		// msg.idiag_ext |= (1 << (INET_DIAG_INFO - 1))
		msg.IDiagExt |= (1 << (api.INET_DIAG_MEMINFO - 1))
		msg.IDiagExt |= (1 << (api.INET_DIAG_SKMEMINFO - 1))
		msg.IDiagExt |= (1 << (api.INET_DIAG_INFO - 1))
		msg.IDiagExt |= (1 << (api.INET_DIAG_VEGASINFO - 1))
		//msg.IDiagExt |= (1 << (api.INET_DIAG_DCTCPINFO - 1))
		//msg.IDiagExt |= (1 << (api.INET_DIAG_BBRINFO - 1))
		msg.IDiagExt |= (1 << (api.INET_DIAG_CONG - 1))
		req.AddData(msg)
	}

	// Copied this from req.Execute in nl_linux.go
	var (
		s   *nl.NetlinkSocket
		err error
	)
	sockType := syscall.NETLINK_INET_DIAG
	if req.Sockets != nil {
		if sh, ok := req.Sockets[sockType]; ok {
			s = sh.Socket
			req.Seq = atomic.AddUint32(&sh.Seq, 1)
		}
	}
	sharedSocket := s != nil

	if s == nil {
		s, err = nl.Subscribe(sockType)
		if err != nil {
			log.Println(err)
			return nil
		}
		defer s.Close()
	} else {
		s.Lock()
		defer s.Unlock()
	}

	if err := s.Send(req); err != nil {
		log.Println(err)
		return nil
	}

	pid, err := s.GetPid()
	if err != nil {
		log.Println(err)
		return nil
	}

	var res []syscall.NetlinkMessage

done:
	for {
		msgs, err := s.Receive()
		if err != nil {
			log.Println(err)
			return nil
		}
		for _, m := range msgs {
			if m.Header.Seq != req.Seq {
				if sharedSocket {
					continue
				}
				log.Printf("Wrong Seq nr %d, expected %d", m.Header.Seq, req.Seq)
				return nil
			}
			if m.Header.Pid != pid {
				log.Printf("Wrong pid %d, expected %d", m.Header.Pid, pid)
				return nil
			}
			if m.Header.Type == unix.NLMSG_DONE {
				break done
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				native := nl.NativeEndian()
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				log.Println(syscall.Errno(-error))
				return nil
			}
			//	if resType != 0 && m.Header.Type != resType {
			//		continue
			//	}
			res = append(res, m)
			if m.Header.Flags&unix.NLM_F_MULTI == 0 {
				break done
			}
		}
	}

	return res
}

// ParseNetlinkRouteAttr parses m's payload as an array of netlink
// route attributes and returns the slice containing the
// NetlinkRouteAttr structures.
func ParseNetlinkRouteAttr(m *syscall.NetlinkMessage) ([]syscall.NetlinkRouteAttr, error) {
	var b []byte

	switch m.Header.Type {
	case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
		log.Printf("using SizeofIfInfomsg: %d\n", syscall.SizeofIfInfomsg)
		b = m.Data[syscall.SizeofIfInfomsg:]
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		log.Printf("using SizeofIfAddrmsg: %d\n", syscall.SizeofIfAddrmsg)
		b = m.Data[syscall.SizeofIfAddrmsg:]
	case syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE:
		log.Printf("using SizeofRtMsg: %d\n", syscall.SizeofRtMsg)
		b = m.Data[syscall.SizeofRtMsg:]
	default:
		return nil, syscall.EINVAL
	}
	var attrs []syscall.NetlinkRouteAttr
	log.Printf("Data len: %d\n", len(b))
	for len(b) >= syscall.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: *a, Value: vbuf[:int(a.Len)-syscall.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

func netlinkRouteAttrAndValue(b []byte) (*syscall.RtAttr, []byte, int, error) {
	a := (*syscall.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < syscall.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, syscall.EINVAL
	}
	return a, b[syscall.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}

// Round the length of a netlink route attribute up to align it
// properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + syscall.RTA_ALIGNTO - 1) & ^(syscall.RTA_ALIGNTO - 1)
}
