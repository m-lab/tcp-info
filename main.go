package main

// For comparison, try
// sudo ss -timep | grep -A1 -v -e 127.0.0.1 -e skmem | tail

import (
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/trace"
	"syscall"
	"time"

	"github.com/m-lab/go/flagx"

	_ "net/http/pprof" // Support profiling

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

var errCount = 0
var localCount = 0

// Stats prints out some basic cache stats.
// TODO - should also export all of these as Prometheus metrics.  (Issue #32)
func Stats(svr *saver.Saver) {
	stats := svr.Stats()
	log.Printf("Cache info total %d  local %d same %d diff %d new %d err %d\n",
		stats.TotalCount+localCount, localCount,
		stats.TotalCount-(errCount+stats.NewCount+stats.DiffCount+localCount),
		stats.DiffCount, stats.NewCount, errCount)
}

func appendAll(all []*inetdiag.ParsedMessage, msgs []*syscall.NetlinkMessage) {
	ts := time.Now()
	for i := range msgs {
		pm, err := inetdiag.Parse(msgs[i], true)
		if err != nil {
			log.Println(err)
			errCount++
		} else if pm == nil {
			localCount++
		} else {
			pm.Timestamp = ts
			all = append(all, pm)
		}
	}
}

// CollectDefaultNamespace collects all AF_INET6 and AF_INET connection stats, and sends them
// to svr.
func CollectDefaultNamespace(svr chan<- []*inetdiag.ParsedMessage) (int, int) {
	// Preallocate space for up to 500 connections.  We may want to adjust this upwards if profiling
	// indicates a lot of reallocation.
	all := make([]*inetdiag.ParsedMessage, 0, 500)
	remoteCount := 0
	res6, err := inetdiag.OneType(syscall.AF_INET6)
	if err != nil {
		// Properly handle errors
		// TODO add metric
		log.Println(err)
	} else {
		appendAll(all, res6)
	}
	res4, err := inetdiag.OneType(syscall.AF_INET)
	if err != nil {
		// Properly handle errors
		// TODO add metric
		log.Println(err)
	} else {
		appendAll(all, res4)
	}

	// Submit full set of message to the marshalling service.
	svr <- all

	return len(res4) + len(res6), remoteCount
}

var (
	reps        = flag.Int("reps", 0, "How many cycles should be recorded, 0 means continuous")
	enableTrace = flag.Bool("trace", false, "Enable trace")
	promPort    = flag.Int("prom", 9090, "Prometheus metrics export port")
)

func main() {
	flag.Parse()
	flagx.ArgsFromEnv(flag.CommandLine)

	// Performance instrumentation.
	runtime.SetBlockProfileRate(1000000) // 1 sample/msec
	runtime.SetMutexProfileFraction(1000)

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

	ticker := time.NewTicker(10 * time.Millisecond)

	for loops = 0; *reps == 0 || loops < *reps; loops++ {
		total, remote := CollectDefaultNamespace(svrChan)
		totalCount += total
		remoteCount += remote
		// print stats roughly once per minute.
		if loops%6000 == 0 {
			Stats(svr)
		}

		// Wait for next tick.
		<-ticker.C
	}
	ticker.Stop()

	close(svrChan)
	svr.Done.Wait()
	Stats(svr)
	if loops > 0 {
		log.Println(totalCount, "sockets", remoteCount, "remotes", totalCount/loops, "per iteration")
	}
}
