// Package collector repeatedly queries the netlink socket to discover
// measurement data about open TCP connections and sends that data down a
// channel.
package collector

import (
	"context"
	"log"
	"syscall"
	"time"

	"github.com/m-lab/tcp-info/metrics"

	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/saver"
)

var (
	errCount   = 0
	localCount = 0
)

// collectDefaultNamespace collects all AF_INET6 and AF_INET connection stats, and sends them
// to svr.
func collectDefaultNamespace(svr chan<- netlink.MessageBlock, skipLocal bool) (int, int) {
	// Preallocate space for up to 500 connections.  We may want to adjust this upwards if profiling
	// indicates a lot of reallocation.
	buffer := netlink.MessageBlock{}

	remoteCount := 0
	res6, err := OneType(syscall.AF_INET6)
	if err != nil {
		// Properly handle errors
		// TODO add metric
		log.Println(err)
	} else {
		buffer.V6Messages = res6
		buffer.V6Time = time.Now()
	}
	res4, err := OneType(syscall.AF_INET)
	if err != nil {
		// Properly handle errors
		// TODO add metric
		log.Println(err)
	} else {
		buffer.V4Messages = res4
		buffer.V4Time = time.Now()
	}

	// Submit full set of message to the marshalling service.
	svr <- buffer

	return len(res4) + len(res6), remoteCount
}

// Run the collector, either for the specified number of loops, or, if the
// number specified is infinite, run forever.
func Run(ctx context.Context, reps int, svrChan chan<- netlink.MessageBlock, cl saver.CacheLogger, skipLocal bool) (localCount, errCount int) {
	totalCount := 0
	remoteCount := 0
	loops := 0

	// TODO - make this interval programmable.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	lastCollectionTime := time.Now().Add(-10 * time.Millisecond)

	for loops = 0; (reps == 0 || loops < reps) && (ctx.Err() == nil); loops++ {
		total, remote := collectDefaultNamespace(svrChan, skipLocal)
		totalCount += total
		remoteCount += remote
		// print stats roughly once per minute.
		if loops%6000 == 0 {
			cl.LogCacheStats(localCount, errCount)
		}

		now := time.Now()
		interval := now.Sub(lastCollectionTime)
		lastCollectionTime = now
		metrics.PollingHistogram.Observe(interval.Seconds())

		// Wait for next tick.
		<-ticker.C
	}

	if loops > 0 {
		log.Println(totalCount, "sockets", remoteCount, "remotes", totalCount/loops, "per iteration")
	}
	return localCount, errCount
}
