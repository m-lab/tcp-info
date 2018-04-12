package main

// For comparison, try
// sudo ss -timep | grep -A1 -v -e 127.0.0.1 -e skmem | tail

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime/pprof"
	"runtime/trace"
	//"runtime/trace"
	"sync"
	"syscall"

	//	"github.com/gogo/protobuf/proto"

	//"github.com/gogo/protobuf/proto"

	"github.com/golang/protobuf/proto"
	"github.com/m-lab/tcp-info/delta"
	"github.com/m-lab/tcp-info/inetdiag"
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

	// RAW controls whether we just dump raw netlinkMessages, or protobufs.
	// With RAW=true, play takes about 43 seconds to process 10M records,
	// and we see about 1.45 cpu for play, and 0.45 for zstd
	// With RAW=false, play takes about 75 seconds to process 10M records,
	// and we see about 1.31 cpu for play, and 0.32 cpu for zstd
	RAW = false
)

var marshallerChannels []chan *delta.ParsedMessage

// Create a pipe to an external zstd process writing to filename
// Write to io.Writer
// close io.Writer when done
// wait on waitgroup to finish
func ZStdPipe(filename string) (*os.File, *sync.WaitGroup) {
	var wg sync.WaitGroup
	wg.Add(1)
	pipeR, pipeW, _ := os.Pipe()
	f, _ := os.Create(filename)
	cmd := exec.Command("zstd")
	cmd.Stdin = pipeR
	cmd.Stdout = f

	go func() {
		err := cmd.Run()
		if err != nil {
			log.Println("ZSTD error", filename, err)
		}
		pipeR.Close()
		wg.Done()
	}()

	return pipeW, &wg
}

// TODO - lost the RAW output option.
func Marshal(filename string, marshaler chan *delta.ParsedMessage, wg *sync.WaitGroup) {
	pipe, pipeWg := ZStdPipe(filename)
	count := 0
	for {
		count++
		msg, ok := <-marshaler
		if !ok {
			break
		}
		p := tcp.TCPDiagnosticsProto{}
		p.Load(msg.Header, msg.InetDiagMsg, msg.Attributes)
		m, err := proto.Marshal(&p)
		if err != nil {
			log.Println(err)
		} else {
			pipe.Write(m)
		}
	}
	pipe.Close()
	pipeWg.Wait()
	wg.Done()
}

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

var cache = delta.NewCache()

func Queue(msg *delta.ParsedMessage) {
	q := marshallerChannels[int(msg.InetDiagMsg.IDiagInode)%len(marshallerChannels)]
	q <- msg
}

func CloseAll() {
	for i := range marshallerChannels {
		close(marshallerChannels[i])
	}
}

func Demo() (int, int) {
	remoteCount := 0
	res6 := inetdiag.OneType(syscall.AF_INET6)
	for i := range res6 {
		parsed, err := cache.Update(res6[i])
		if err != nil {
			log.Println(err)
		} else if parsed != nil {
			remoteCount++
			Queue(parsed)
		}
	}

	res4 := inetdiag.OneType(syscall.AF_INET)
	for i := range res4 {
		parsed, err := cache.Update(res4[i])
		if err != nil {
			log.Println(err)
		} else if parsed != nil {
			remoteCount++
			Queue(parsed)
		}
	}

	return len(res4) + len(res6), remoteCount
}

var (
	filter      = flag.Bool("filter", true, "Record only records that change")
	reps        = flag.Int("reps", 0, "How manymove the  cycles should be recorded, 0 means continuous")
	verbose     = flag.Bool("v", false, "Enable verbose logging")
	numFiles    = flag.Int("files", 1, "Number of output files")
	enableTrace = flag.Bool("trace", false, "Enable trace")
)

func main() {
	flag.Parse()
	tcp.LOG = *verbose || *reps == 1

	log.Println("Raw:", RAW)
	f, err := os.Create("./foobar")
	if err != nil {
		log.Fatal("Failed to open file")
	}
	defer f.Close()
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

	if *enableTrace {
		traceFile, err := os.Create("trace")
		if err != nil {
			log.Fatal(err)
		}
		if err := trace.Start(traceFile); err != nil {
			log.Fatalf("failed to start trace: %v", err)
		}
		defer trace.Stop()
	}

	var wg sync.WaitGroup
	for i := 0; i < *numFiles; i++ {
		marshChan := make(chan *delta.ParsedMessage, 1000)
		marshallerChannels = append(marshallerChannels, marshChan)
		fn := fmt.Sprintf("file%02d.zst", i)
		wg.Add(1)
		go Marshal(fn, marshChan, &wg)
	}

	totalCount := 0
	remote := 0
	loops := 0
	for *reps == 0 || loops < *reps {
		loops++
		a, b := Demo()
		totalCount += a
		remote += b
		if loops%10 == 0 {
			cache.Stats()
		}
	}
	cache.Stats()
	if loops > 0 {
		log.Println(totalCount, "sockets", remote, "remotes", totalCount/loops, "per iteration")
	}

	CloseAll()
	wg.Wait()

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
