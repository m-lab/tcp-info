package main

// For comparison, try
// sudo ss -timep | grep -A1 -v -e 127.0.0.1 -e skmem | tail

import (
	"context"
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/trace"

	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"

	"github.com/m-lab/go/flagx"

	_ "net/http/pprof" // Support profiling

	"github.com/m-lab/tcp-info/collector"
	"github.com/m-lab/tcp-info/inetdiag"
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

var (
	reps        = flag.Int("reps", 0, "How many cycles should be recorded, 0 means continuous")
	enableTrace = flag.Bool("trace", false, "Enable trace")
	promPort    = flag.String("prom", ":9090", "Prometheus metrics export address and port. Default is ':9090'")
	outputDir   = flag.String("output", "", "Directory in which to put the resulting tree of data.  Default is the current directory.")

	ctx, cancel = context.WithCancel(context.Background())
)

func main() {
	flag.Parse()
	flagx.ArgsFromEnv(flag.CommandLine)

	if *outputDir != "" {
		rtx.Must(os.Chdir(*outputDir), "Could not change to the directory %s", *outputDir)
	}

	// Performance instrumentation.
	runtime.SetBlockProfileRate(1000000) // 1 sample/msec
	runtime.SetMutexProfileFraction(1000)

	// Expose prometheus and pprof metrics on a separate port.
	promSrv := prometheusx.MustStartPrometheus(*promPort)
	defer promSrv.Shutdown(ctx)

	if *enableTrace {
		traceFile, err := os.Create("trace")
		rtx.Must(err, "Could not creat trace file")
		rtx.Must(trace.Start(traceFile), "failed to start trace: %v", err)
		defer trace.Stop()
	}

	// Make the saver and construct the message channel, buffering up to 2 batches
	// of messages without stalling producer. We may want to increase the buffer if
	// we observe main() stalling.
	svrChan := make(chan []*inetdiag.ParsedMessage, 2)
	svr := saver.NewSaver("host", "pod", 3)
	go svr.MessageSaverLoop(svrChan)

	// Run the collector, possibly forever.
	totalSeen, totalErr := collector.Run(ctx, *reps, svrChan, svr, true)

	// Shut down and clean up after the collector terminates.
	close(svrChan)
	svr.Done.Wait()
	svr.LogCacheStats(totalSeen, totalErr)
}
