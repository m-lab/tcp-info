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
	"runtime/trace"
	"sync"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/golang/protobuf/proto"

	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
	tcp "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/nl-proto/pbtools"
	"github.com/m-lab/tcp-info/saver"
	"github.com/m-lab/tcp-info/zstd"
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

func Marshal(filename string, marshaler chan *inetdiag.ParsedMessage, wg *sync.WaitGroup) error {
	out, err := zstd.NewWriter(filename)
	if err != nil {
		return err
	}
	count := 0
	for {
		count++
		msg, ok := <-marshaler
		if !ok {
			break
		}
		p := pbtools.CreateProto(msg.Timestamp, msg.Header, msg.InetDiagMsg, msg.Attributes[:])
		m, err := proto.Marshal(p)
		if err != nil {
			log.Println(err)
		} else {
			out.Write(m)
		}
	}
	out.Close()
	wg.Done()
	return nil
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

// Stats prints out some basic cache stats.
// TODO - should also export all of these as Prometheus metrics.  (Issue #32)
func Stats() {
	log.Printf("Cache info total %d  local %d same %d diff %d new %d err %d\n",
		totalCount, localCount,
		totalCount-(errCount+newCount+diffCount+localCount),
		diffCount, newCount, errCount)
}

func ParseAndQueue(cache *cache.Cache, msg *syscall.NetlinkMessage, queue bool) *inetdiag.ParsedMessage {
	totalCount++
	pm, err := inetdiag.Parse(msg, true)
	if err != nil {
		log.Println(err)
		errCount++
	} else if pm == nil {
		localCount++
	} else {
		if !queue {
			return pm
		}
		old := cache.Update(pm)
		if old == nil {
			newCount++
			Queue(pm)
		} else {
			if pbtools.Compare(pm, old) > 0 {
				if rawOut != nil {
					binary.Write(rawOut, binary.BigEndian, msg.Header)
					binary.Write(rawOut, binary.BigEndian, msg.Data)
				}
				diffCount++
				Queue(pm)
			}
		}
	}
	return nil
}

func Demo(cache *cache.Cache, svr chan<- []*inetdiag.ParsedMessage) (int, int) {
	all := make([]*inetdiag.ParsedMessage, 0, 500)
	remoteCount := 0
	res6, _ := inetdiag.OneType(syscall.AF_INET6) // Ignoring errors in Demo code
	ts := time.Now()
	for i := range res6 {
		pm := ParseAndQueue(cache, res6[i], false)
		if pm != nil {
			pm.Timestamp = ts
			all = append(all, pm)
		}
	}

	res4, _ := inetdiag.OneType(syscall.AF_INET) // Ignoring errors in Demo code
	ts = time.Now()
	for i := range res4 {
		pm := ParseAndQueue(cache, res4[i], false)
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
	filter      = flag.Bool("filter", true, "Record only records that change")
	reps        = flag.Int("reps", 0, "How many cycles should be recorded, 0 means continuous")
	verbose     = flag.Bool("v", false, "Enable verbose logging")
	numFiles    = flag.Int("files", 1, "Number of output files")
	enableTrace = flag.Bool("trace", false, "Enable trace")
	rawFile     = flag.String("raw", "", "File to write raw records to")
	source      = flag.String("source", "", "Source to read (uncompressed) NetlinkMessage records")
	promPort    = flag.Int("prom", 9090, "Prometheus metrics export port")
)

var rawOut io.WriteCloser

func main() {
	// TODO - use flagx.ArgsFromEnv

	metrics.SetupPrometheus(*promPort)

	if *rawFile != "" {
		log.Println("Raw output to", *rawFile)
		var err error
		rawOut, err = zstd.NewWriter(*rawFile)
		if err != nil {
			log.Fatal("Could not open raw output file", *rawFile)
		}
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
			ParseAndQueue(msgCache, msg, true)
		}
		Stats()
	} else {
		totalCount := 0
		remoteCount := 0
		loops := 0
		svr := saver.NewSaver("host", "pod", 3)

		// Construct message channel, buffering up to 2 batches of messages without stalling producer.
		// We may want to increase this if we observe main() stalling.
		svrChan := make(chan []*inetdiag.ParsedMessage, 2)
		go svr.MessageSaverLoop(svrChan)

		for loops = 0; *reps == 0 || loops < *reps; loops++ {
			total, remote := Demo(msgCache, svrChan)
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

	//log.Printf("%+v\n", delta.DiffCounts)
	CloseAll()
	wg.Wait()

}
