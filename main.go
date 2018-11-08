package main

// For comparison, try
// sudo ss -timep | grep -A1 -v -e 127.0.0.1 -e skmem | tail

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"os"
	"runtime/trace"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/golang/protobuf/proto"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
	tcp "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/saver"
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

var totalCount = 0
var errCount = 0
var localCount = 0
var newCount = 0
var diffCount = 0

// Stats prints out some basic cache stats.
// TODO - should also export all of these as Prometheus metrics.  (Issue #32)
func Stats() {
	log.Printf("Cache info total %d  local %d same %d diff %d new %d err %d\n",
		totalCount, localCount,
		totalCount-(errCount+newCount+diffCount+localCount),
		diffCount, newCount, errCount)
}

func Parse(msg *syscall.NetlinkMessage) *inetdiag.ParsedMessage {
	totalCount++
	pm, err := inetdiag.Parse(msg, true)
	if err != nil {
		log.Println(err)
		errCount++
		return nil
	}
	if pm == nil {
		localCount++
	}
	return pm
}

func Demo(svr chan<- []*inetdiag.ParsedMessage) (int, int) {
	all := make([]*inetdiag.ParsedMessage, 0, 500)
	remoteCount := 0
	res6, _ := inetdiag.OneType(syscall.AF_INET6) // Ignoring errors in Demo code
	ts := time.Now()
	for i := range res6 {
		pm := Parse(res6[i])
		if pm != nil {
			pm.Timestamp = ts
			all = append(all, pm)
		}
	}

	res4, _ := inetdiag.OneType(syscall.AF_INET) // Ignoring errors in Demo code
	ts = time.Now()
	for i := range res4 {
		pm := Parse(res4[i])
		if pm != nil {
			pm.Timestamp = ts
			all = append(all, pm)
		}
	}

	svr <- all

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
	reps        = flag.Int("reps", 0, "How many cycles should be recorded, 0 means continuous")
	enableTrace = flag.Bool("trace", false, "Enable trace")
	promPort    = flag.Int("prom", 9090, "Prometheus metrics export port")
)

func main() {
	// TODO - use flagx.ArgsFromEnv

	metrics.SetupPrometheus(*promPort)

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

	totalCount := 0
	remoteCount := 0
	loops := 0
	svr := saver.NewSaver("host", "pod", 3)

	// Construct message channel, buffering up to 2 batches of messages without stalling producer.
	// We may want to increase this if we observe main() stalling.
	svrChan := make(chan []*inetdiag.ParsedMessage, 2)
	go svr.MessageSaverLoop(svrChan)

	for loops = 0; *reps == 0 || loops < *reps; loops++ {
		total, remote := Demo(svrChan)
		totalCount += total
		remoteCount += remote
		if loops%10000 == 0 {
			Stats()
			svr.Stats()
		}
	}

	close(svrChan)
	svr.Done.Wait()
	Stats()
	if loops > 0 {
		log.Println(totalCount, "sockets", remoteCount, "remotes", totalCount/loops, "per iteration")
	}
}
