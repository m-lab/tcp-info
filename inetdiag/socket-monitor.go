package inetdiag

/*
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
import "C"
*/

import (
	"log"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/m-lab/tcp-info/metrics"
	tcpinfo "github.com/m-lab/tcp-info/nl-proto"
)

const TCPF_ALL = 0xFFF

func makeReq(inetType uint8) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST)
	msg := NewInetDiagReqV2(inetType, syscall.IPPROTO_TCP,
		TCPF_ALL & ^((1<<uint(tcpinfo.TCPState_SYN_RECV))|(1<<uint(tcpinfo.TCPState_TIME_WAIT))|(1<<uint(tcpinfo.TCPState_CLOSE))))
	msg.IDiagExt |= (1 << (INET_DIAG_MEMINFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_INFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_VEGASINFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_CONG - 1))

	msg.IDiagExt |= (1 << (INET_DIAG_TCLASS - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_TOS - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_SKMEMINFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_SHUTDOWN - 1))

	//msg.IDiagExt |= (1 << (INET_DIAG_DCTCPINFO - 1))
	//msg.IDiagExt |= (1 << (INET_DIAG_BBRINFO - 1))

	req.AddData(msg)
	req.NlMsghdr.Type = SOCK_DIAG_BY_FAMILY
	req.NlMsghdr.Flags |= syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST
	return req
}

// OneType handles the request and response for a single type, e.g. INET or INET6
// TODO maybe move this to top level?
func OneType(inetType uint8) []*syscall.NetlinkMessage {
	start := time.Now()
	req := makeReq(inetType)

	// Copied this from req.Execute in nl_linux.go
	sockType := syscall.NETLINK_INET_DIAG
	s, err := nl.Subscribe(sockType)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer s.Close()

	if err := s.Send(req); err != nil {
		log.Println(err)
		return nil
	}

	pid, err := s.GetPid()
	if err != nil {
		log.Println(err)
		return nil
	}

	var res []*syscall.NetlinkMessage

done:
	// Adapted this from req.Execute in nl_linux.go
	for {
		msgs, err := s.Receive()
		if err != nil {
			log.Println(err)
			return nil
		}
		// TODO avoid the copy.
		for i := range msgs {
			m := &msgs[i]
			if m.Header.Seq != req.Seq {
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

	switch inetType {
	case syscall.AF_INET:
		metrics.FetchTimeSummary.With(prometheus.Labels{"af": "ipv4"}).Observe(float64(time.Since(start).Nanoseconds()))
	case syscall.AF_INET6:
		metrics.FetchTimeSummary.With(prometheus.Labels{"af": "ipv6"}).Observe(float64(time.Since(start).Nanoseconds()))
	default:
		metrics.FetchTimeSummary.With(prometheus.Labels{"af": "unknown"}).Observe(float64(time.Since(start).Nanoseconds()))
	}

	return res
}
