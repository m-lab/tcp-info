package main

// For comparison, try
// sudo ss -timep | grep -A1 -v -e 127.0.0.1 -e skmem | tail

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"syscall"

	"github.com/golang/protobuf/proto"
	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/inetdiag"
	tcp "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/nl-proto/tools"
	"github.com/m-lab/tcp-info/zstd"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

/*
Some performance numbers
flat  flat%   sum%        cum   cum%
3.99s 79.48% 79.48%         4s 79.68%  syscall.Syscall6
0.11s  2.19% 81.67%      0.41s  8.17%  runtime.mallocgc
0.10s  1.99% 83.67%      0.10s  1.99%  runtime.heapBitsSetType
0.08s  1.59% 85.26%      0.08s  1.59%  runtime.futex
0.06s  1.20% 86.45%      0.06s  1.20%  runtime.memclrNoHeapPointers
0.06s  1.20% 87.65%      0.08s  1.59%  runtime.scanobject
0.06s  1.20% 88.84%      0.06s  1.20%  syscall.RawSyscall
0.04s   0.8% 89.64%      0.07s  1.39%  github.com/m-lab/tcp-info/delta.(*ParsedMessage).IsSame
0.04s   0.8% 90.44%      0.12s  2.39%  runtime.(*mcentral).cacheSpan
0.04s   0.8% 91.24%      0.04s   0.8%  runtime.duffcopy
0.04s   0.8% 92.03%      0.04s   0.8%  runtime.memmove
0.04s   0.8% 92.83%      0.04s   0.8%  syscall.Syscall
0.03s   0.6% 93.43%      0.03s   0.6%  runtime.cmpbody
0.03s   0.6% 94.02%      0.03s   0.6%  runtime.heapBitsForObject
0.02s   0.4% 94.42%      0.20s  3.98%  github.com/vishvananda/netlink/nl.ParseRouteAttr
0.02s   0.4% 94.82%      0.14s  2.79%  runtime.(*mcache).refill
0.02s   0.4% 95.22%      0.35s  6.97%  runtime.growslice
0.01s   0.2% 95.42%      0.38s  7.57%  github.com/m-lab/tcp-info/delta.(*Cache).Update
0.01s   0.2% 95.62%      0.10s  1.99%  runtime.gcDrain
0.01s   0.2% 95.82%      0.07s  1.39%  runtime.makeslice
*/

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// NOTES:
//  1. zstd is much better than gzip
//  2. the go zstd wrapper doesn't seem to work well - poor compression and slow.
//  3. zstd seems to result in similar file size using proto or raw output.

func Marshal(filename string, marshaler chan *inetdiag.ParsedMessage, wg *sync.WaitGroup) {
	out, pipeWg := zstd.NewWriter(filename)
	count := 0
	for {
		count++
		msg, ok := <-marshaler
		if !ok {
			break
		}
		p := tools.CreateProto(msg.Header, msg.InetDiagMsg, msg.Attributes[:])
		if false {
			log.Printf("%+v\n", p.InetDiagMsg)
			log.Printf("%+v\n", p.TcpInfo)
			log.Printf("%+v\n", p.SocketMem)
			log.Printf("%+v\n", p.MemInfo)
			log.Printf("%+v\n", p.CongestionAlgorithm)
		}
		m, err := proto.Marshal(p)
		if err != nil {
			log.Println(err)
		} else {
			out.Write(m)
		}
	}
	out.Close()
	pipeWg.Wait()
	wg.Done()
}

var marshallerChannels []chan *inetdiag.ParsedMessage

func Queue(msg *inetdiag.ParsedMessage) {
	q := marshallerChannels[int(msg.InetDiagMsg.IDiagInode)%len(marshallerChannels)]
	q <- msg
}

func CloseAll() {
	for i := range marshallerChannels {
		close(marshallerChannels[i])
	}
}

var totalCount = 0
var errCount = 0
var localCount = 0
var newCount = 0
var diffCount = 0
var expiredCount = 0

func Stats() {
	log.Printf("Cache info total %d  local %d same %d diff %d new %d closed %d err %d\n",
		totalCount, localCount,
		totalCount-(errCount+newCount+diffCount+localCount),
		diffCount, newCount, expiredCount, errCount)
}

func ParseAndQueue(cache *cache.Cache, msg *syscall.NetlinkMessage) {
	totalCount++
	pm, err := inetdiag.Parse(msg, true)
	if err != nil {
		log.Println(err)
		errCount++
	} else if pm == nil {
		localCount++
	} else {
		old := cache.Update(pm)
		if old == nil {
			newCount++
		} else {
			if tools.Compare(pm, old) > 0 {
				if rawOut != nil {
					binary.Write(rawOut, binary.BigEndian, msg.Header)
					binary.Write(rawOut, binary.BigEndian, msg.Data)
				}
				diffCount++
				Queue(pm)
			}
		}
	}
}

func Demo(cache *cache.Cache) (int, int) {
	remoteCount := 0
	res6 := inetdiag.OneType(syscall.AF_INET6)
	for i := range res6 {
		ParseAndQueue(cache, res6[i])
	}

	res4 := inetdiag.OneType(syscall.AF_INET)
	for i := range res4 {
		ParseAndQueue(cache, res4[i])
	}

	residual := cache.EndCycle()
	expiredCount += len(residual)
	for i := range residual {
		// TODO should also write to rawOut, but don't have the original msg.
		log.Println(residual[i].InetDiagMsg)
	}

	return len(res4) + len(res6), remoteCount
}

// NextMsg reads the next NetlinkMessage from a source readers.
func NextMsg(rdr io.Reader) (*syscall.NetlinkMessage, error) {
	var header syscall.NlMsghdr
	err := binary.Read(rdr, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	//log.Printf("%+v\n", header)
	data := make([]byte, header.Len-uint32(binary.Size(header)))
	err = binary.Read(rdr, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	return &syscall.NetlinkMessage{Header: header, Data: data}, nil
}

var (
	filter      = flag.Bool("filter", true, "Record only records that change")
	reps        = flag.Int("reps", 0, "How manymove the  cycles should be recorded, 0 means continuous")
	verbose     = flag.Bool("v", false, "Enable verbose logging")
	numFiles    = flag.Int("files", 1, "Number of output files")
	enableTrace = flag.Bool("trace", false, "Enable trace")
	rawFile     = flag.String("raw", "", "File to write raw records to")
	source      = flag.String("source", "", "Source to read (uncompressed) NetlinkMessage records")
)

var rawOut io.WriteCloser

func main() {
	flag.Parse()
	// TODO ? tcp.LOG = *verbose || *reps == 1

	if *rawFile != "" {
		log.Println("Raw output to", *rawFile)
		var wg *sync.WaitGroup
		rawOut, wg = zstd.NewWriter(*rawFile)
		defer wg.Wait()
		defer rawOut.Close()
	}

	msgCache := cache.NewCache()

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
		marshChan := make(chan *inetdiag.ParsedMessage, 1000)
		marshallerChannels = append(marshallerChannels, marshChan)
		fn := fmt.Sprintf("file%02d.zst", i)
		wg.Add(1)
		go Marshal(fn, marshChan, &wg)
	}

	if *source != "" {
		log.Println("Reading messages from", *source)
		rdr := zstd.NewReader(*source)
		for {
			msg, err := NextMsg(rdr)
			if err != nil {
				break
			}
			ParseAndQueue(msgCache, msg)
		}
		Stats()
	} else {
		totalCount := 0
		remote := 0
		loops := 0
		for *reps == 0 || loops < *reps {
			loops++
			a, b := Demo(msgCache)
			totalCount += a
			remote += b
			if loops%50 == 0 {
				Stats()
			}
		}
		Stats()
		if loops > 0 {
			log.Println(totalCount, "sockets", remote, "remotes", totalCount/loops, "per iteration")
		}
	}

	//log.Printf("%+v\n", delta.DiffCounts)
	CloseAll()
	wg.Wait()

}

func otherStuff() {
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
