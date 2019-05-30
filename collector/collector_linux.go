// Package collector repeatedly queries the netlink socket to discover
// measurement data about open TCP connections and sends that data down a
// channel.
package collector

import (
	"context"
	"log"
	"syscall"
	"time"

	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/saver"
)

var (
	errCount   = 0
	localCount = 0
)

func appendAll(all []*netlink.ArchivalRecord, msgs []*netlink.NetlinkMessage, skipLocal bool) []*netlink.ArchivalRecord {
	// We use UTC, and truncate to millisecond to improve compression.
	// Since the syscall to collect the data takes multiple milliseconds, this truncation seems reasonable.
	ts := time.Now().UTC().Truncate(time.Millisecond)
	for i := range msgs {
		pm, err := netlink.MakeArchivalRecord(msgs[i], skipLocal)
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
	return all
}

// collectDefaultNamespace collects all AF_INET6 and AF_INET connection stats, and sends them
// to svr.
func collectDefaultNamespace(svr chan<- []*netlink.ArchivalRecord, skipLocal bool) (int, int) {
	// Preallocate space for up to 500 connections.  We may want to adjust this upwards if profiling
	// indicates a lot of reallocation.
	all := make([]*netlink.ArchivalRecord, 0, 500)
	remoteCount := 0
	res6, err := OneType(syscall.AF_INET6)
	if err != nil {
		// Properly handle errors
		// TODO add metric
		log.Println(err)
	} else {
		all = appendAll(all, res6, skipLocal)
	}
	res4, err := OneType(syscall.AF_INET)
	if err != nil {
		// Properly handle errors
		// TODO add metric
		log.Println(err)
	} else {
		all = appendAll(all, res4, skipLocal)
	}

	// Submit full set of message to the marshalling service.
	svr <- all

	return len(res4) + len(res6), remoteCount
}

// Run the collector, either for the specified number of loops, or, if the
// number specified is infinite, run forever.
func Run(ctx context.Context, reps int, svrChan chan<- []*netlink.ArchivalRecord, cl saver.CacheLogger, skipLocal bool) (localCount, errCount int) {
	totalCount := 0
	remoteCount := 0
	loops := 0

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for loops = 0; (reps == 0 || loops < reps) && (ctx.Err() == nil); loops++ {
		total, remote := collectDefaultNamespace(svrChan, skipLocal)
		totalCount += total
		remoteCount += remote
		// print stats roughly once per minute.
		if loops%6000 == 0 {
			cl.LogCacheStats(localCount, errCount)
		}

		// Wait for next tick.
		<-ticker.C
	}

	if loops > 0 {
		log.Println(totalCount, "sockets", remoteCount, "remotes", totalCount/loops, "per iteration")
	}
	return localCount, errCount
}
