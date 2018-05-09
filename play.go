package main

import (
	"log"
	"os"
	"runtime/pprof"
	"syscall"

	//	"github.com/gogo/protobuf/proto"

	//"github.com/gogo/protobuf/proto"

	"github.com/golang/protobuf/proto"
	"github.com/m-lab/tcp-info/other"
	"github.com/m-lab/tcp-info/tcp"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// NOTES:
//  1. zstd is much better than gzip
//  2. the go zstd wrapper doesn't seem to work well - poor compression and slow.
//  3. zstd seems to result in similar file size using proto or raw output.

const (
	TCPDIAG_GETSOCK     = 18 // linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // linux/sock_diag.h

	RAW = false
)

var Out = os.Stdout

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func Demo() int {
	res6 := other.OneType(syscall.AF_INET6)
	for i := range res6 {
		p := tcp.TCPDiagnosticsProto{}
		p.LoadFromAttr(&res6[i])
		if RAW {
			other.OutBuf.Write(res6[i].Data)
		} else {
			m, err := proto.Marshal(&p)
			if err != nil {
				log.Println(err)
			} else {
				Out.Write(m)
			}
		}
	}

	res4 := other.OneType(syscall.AF_INET)
	for i := range res4 {
		p := tcp.TCPDiagnosticsProto{}
		p.LoadFromAttr(&res4[i])
		if RAW {
			other.OutBuf.Write(res4[i].Data)
		} else {
			m, err := proto.Marshal(&p)
			if err != nil {
				log.Println(err)
			} else {
				Out.Write(m)
			}
		}
	}

	return len(res4) + len(res6)
}

func main() {
	log.Println("Raw:", RAW)
	f, err := os.Create("./foobar")
	if err != nil {
		log.Fatal("Failed to open file")
	}
	defer f.Close()
	// Out = zstd.NewWriter(bufio.NewWriter(f))
	// defer Out.Close()

	p := tcp.TCPDiagnosticsProto{}
	p.TcpInfo = &tcp.TCPInfoProto{}
	// This generates quite a large byte array - 144 bytes for JUST TCPInfo,
	// but perhaps they are highly compressible?

	m, err := proto.Marshal(&p)
	if err != nil {
		log.Println(err)
	} else {
		log.Println(len(m), m)
	}

	prof, err := os.Create("profile")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(prof)
	defer pprof.StopCPUProfile()

	sockCount := 0
	if tcp.LOG {
		sockCount = Demo()
	} else {

		for i := 0; i < 1000; i++ {
			sockCount = Demo()
		}
	}
	log.Println(sockCount, "sockets")

	return

	// OTHER STUFF
	fd, err := unix.Socket(
		// Always used when opening netlink sockets.
		unix.AF_NETLINK,
		// Seemingly used interchangeably with SOCK_DGRAM,
		// but it appears not to matter which is used.
		unix.SOCK_RAW,
		// The netlink family that the socket will communicate
		// with, such as NETLINK_ROUTE or NETLINK_GENERIC.
		unix.NETLINK_ROUTE)

	if err != nil {
		log.Println(err)
	}

	err = unix.Bind(fd, &unix.SockaddrNetlink{
		// Always used when binding netlink sockets.
		Family: unix.AF_NETLINK,
		// A bitmask of multicast groups to join on bind.
		// Typically set to zero.
		Groups: 0,
		// If you'd like, you can assign a PID for this socket
		// here, but in my experience, it's easier to leave
		// this set to zero and let netlink assign and manage
		// PIDs on its own.
		Pid: 0,
	})
	if err != nil {
		log.Println(err)
	}

	msg := netlink.Message{
		Header: netlink.Header{
			// Length of header, plus payload.
			Length: 0,
			// Set to zero on requests.
			Type: 0,
			// Indicate that message is a request to the kernel.
			Flags: netlink.HeaderFlagsRequest,
			// Sequence number selected at random.
			Sequence: 1,
			// PID set to process's ID.
			PID: uint32(os.Getpid()),
		},
		// An arbitrary byte payload. May be in a variety of formats.
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	}

	log.Printf("%+v\n", msg)
	/*
		err = unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{
			// Always used when sending on netlink sockets.
			Family: unix.AF_NETLINK,
		})

		b := make([]byte, os.Getpagesize())
		for {
			// Peek at the buffer to see how many bytes are available.
			n, _, _ := unix.Recvfrom(fd, b, unix.MSG_PEEK)
			// Break when we can read all messages.
			if n < len(b) {
				break
			}
			// Double in size if not enough bytes.
			b = make([]byte, len(b)*2)
		}
		// Read out all available messages.
		n, _, _ := unix.Recvfrom(fd, b, 0) */

	// Speak to generic netlink using netlink
	const familyGeneric = 16

	c, err := netlink.Dial(familyGeneric, nil)
	if err != nil {
		log.Fatalf("failed to dial netlink: %v", err)
	}
	defer c.Close()

	// Ask netlink to send us an acknowledgement, which will contain
	// a copy of the header we sent to it
	req := netlink.Message{
		Header: netlink.Header{
			// Package netlink will automatically set header fields
			// which are set to zero
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
		},
	}

	// Perform a request, receive replies, and validate the replies
	msgs, err := c.Execute(req)
	if err != nil {
		log.Fatalf("failed to execute request: %v", err)
	}

	if c := len(msgs); c != 1 {
		log.Fatalf("expected 1 message, but got: %d", c)
	}

	// Decode the copied request header, starting after 4 bytes
	// indicating "success"
	var res netlink.Message
	if err := (&res).UnmarshalBinary(msgs[0].Data[4:]); err != nil {
		log.Fatalf("failed to unmarshal response: %v", err)
	}

	log.Printf("res: %+v", res)

}
