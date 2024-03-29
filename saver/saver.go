// Package saver contains all logic for writing records to files.
//  1. Sets up a channel that accepts slices of *netlink.ArchivalRecord
//  2. Maintains a map of Connections, one for each connection.
//  3. Uses several marshallers goroutines to serialize data and and write to
//     zstd files.
//  4. Rotates Connection output files every 10 minutes for long lasting connections.
//  5. uses a cache to detect meaningful state changes, and avoid excessive
//     writes.
package saver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m-lab/go/anonymize"

	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/tcp"
	"github.com/m-lab/tcp-info/zstd"
	"github.com/m-lab/uuid"
)

// This is the maximum switch/network if speed in bits/sec.  It is used to check for illogical bit rate observations.
const maxSwitchSpeed = 1e10

// We will send an entire batch of prefiltered ArchivalRecords through a channel from
// the collection loop to the top level saver.  The saver will detect new connections
// and significant diffs, maintain the connection cache, determine
// how frequently to save deltas for each connection.
//
// The saver will use a small set of Marshallers to convert to protos,
// marshal the protos, and write them to files.

// Errors generated by saver functions.
var (
	ErrNoMarshallers = errors.New("Saver has zero Marshallers")
)

// Task represents a single marshalling task, specifying the message and the writer.
type Task struct {
	// nil message means close the writer.
	Message *netlink.ArchivalRecord
	Writer  io.WriteCloser
}

// CacheLogger is any object with a LogCacheStats method.
type CacheLogger interface {
	LogCacheStats(localCount, errCount int)
}

// MarshalChan is a channel of marshalling tasks.
type MarshalChan chan<- Task

func runMarshaller(taskChan <-chan Task, wg *sync.WaitGroup, anon anonymize.IPAnonymizer) {
	for task := range taskChan {
		if task.Message == nil {
			task.Writer.Close()
			continue
		}
		if task.Writer == nil {
			log.Fatal("Nil writer")
		}
		err := task.Message.RawIDM.Anonymize(anon)
		if err != nil {
			log.Println("Failed to anonymize message:", err)
			continue
		}
		b, _ := json.Marshal(task.Message) // FIXME: don't ignore error
		task.Writer.Write(b)
		task.Writer.Write([]byte("\n"))
	}
	log.Println("Marshaller Done")
	wg.Done()
}

func newMarshaller(wg *sync.WaitGroup, anon anonymize.IPAnonymizer) MarshalChan {
	marshChan := make(chan Task, 100)
	wg.Add(1)
	go runMarshaller(marshChan, wg, anon)
	return marshChan
}

// Connection objects handle all output associated with a single connection.
type Connection struct {
	Inode      uint32 // TODO - also use the UID???
	ID         inetdiag.SockID
	UID        uint32
	Slice      string    // 4 hex, indicating which machine segment this is on.
	StartTime  time.Time // Time the connection was initiated.
	Sequence   int       // Typically zero, but increments for long running connections.
	Expiration time.Time // Time we will swap files and increment Sequence.
	Writer     io.WriteCloser
}

func newConnection(info *inetdiag.InetDiagMsg, timestamp time.Time) *Connection {
	conn := Connection{Inode: info.IDiagInode, ID: info.ID.GetSockID(), UID: info.IDiagUID, Slice: "", StartTime: timestamp, Sequence: 0,
		Expiration: time.Now()}
	return &conn
}

// Rotate opens the next writer for a connection.
// Note that long running connections will have data in multiple directories,
// because, for all segments after the first one, we choose the directory
// based on the time Rotate() was called, and not on the StartTime of the
// connection. Long-running connections with data on multiple days will
// therefore likely have data in multiple date directories.
// (This behavior is new as of April 2020. Prior to then, all files were
// placed in the directory corresponding to the StartTime.)
func (conn *Connection) Rotate(Host string, Pod string, FileAgeLimit time.Duration) error {
	datePath := conn.StartTime.Format("2006/01/02")
	// For first block, date directory is based on the connection start time.
	// For all other blocks, (sequence > 0) it is based on the current time.
	if conn.Sequence > 0 {
		now := time.Now().UTC()
		datePath = now.Format("2006/01/02")
	}
	err := os.MkdirAll(datePath, 0777)
	if err != nil {
		return err
	}
	id := uuid.FromCookie(conn.ID.CookieUint64())
	conn.Writer, err = zstd.NewWriter(fmt.Sprintf("%s/%s.%05d.jsonl.zst", datePath, id, conn.Sequence))
	if err != nil {
		return err
	}
	conn.writeHeader()
	metrics.NewFileCount.Inc()
	conn.Expiration = conn.Expiration.Add(10 * time.Minute)
	conn.Sequence++
	return nil
}

func (conn *Connection) writeHeader() {
	msg := netlink.ArchivalRecord{
		Metadata: &netlink.Metadata{
			UUID:      uuid.FromCookie(conn.ID.CookieUint64()),
			Sequence:  conn.Sequence,
			StartTime: conn.StartTime,
		},
	}
	// FIXME: Error handling
	bytes, _ := json.Marshal(msg)
	conn.Writer.Write(bytes)
	conn.Writer.Write([]byte("\n"))
}

type stats struct {
	TotalCount   int64
	NewCount     int64
	DiffCount    int64
	ExpiredCount int64
}

func (s *stats) IncTotalCount() {
	atomic.AddInt64(&s.TotalCount, 1)
}

func (s *stats) IncNewCount() {
	atomic.AddInt64(&s.NewCount, 1)
}

func (s *stats) IncDiffCount() {
	atomic.AddInt64(&s.DiffCount, 1)
}

func (s *stats) IncExpiredCount() {
	atomic.AddInt64(&s.ExpiredCount, 1)
}

func (s *stats) Copy() stats {
	result := stats{}
	result.TotalCount = atomic.LoadInt64(&s.TotalCount)
	result.NewCount = atomic.LoadInt64(&s.NewCount)
	result.DiffCount = atomic.LoadInt64(&s.DiffCount)
	result.ExpiredCount = atomic.LoadInt64(&s.ExpiredCount)
	return result
}

// TcpStats is used to save the connection stats as connection is closing.
type TcpStats struct {
	Sent     uint64 // BytesSent
	Received uint64 // BytesReceived
}

// Saver provides functionality for saving tcpinfo diffs to connection files.
// It handles arbitrary connections, and only writes to file when the
// significant fields change.  (TODO - what does "significant fields" mean).
// TODO - just export an interface, instead of the implementation.
type Saver struct {
	Host          string // mlabN
	Pod           string // 3 alpha + 2 decimal
	FileAgeLimit  time.Duration
	MarshalChans  []MarshalChan
	Done          *sync.WaitGroup // All marshallers will call Done on this.
	Connections   map[uint64]*Connection
	ClosingStats  map[uint64]TcpStats // BytesReceived and BytesSent for connections that are closing.
	ClosingTotals TcpStats

	cache       *cache.Cache
	stats       stats
	eventServer eventsocket.Server
	exclude     *netlink.ExcludeConfig
}

// NewSaver creates a new Saver for the given host and pod.  numMarshaller controls
// how many marshalling goroutines are used to distribute the marshalling workload.
func NewSaver(host string, pod string, numMarshaller int, srv eventsocket.Server, anon anonymize.IPAnonymizer, ex *netlink.ExcludeConfig) *Saver {
	m := make([]MarshalChan, 0, numMarshaller)
	c := cache.NewCache()
	// We start with capacity of 500.  This will be reallocated as needed, but this
	// is not a performance concern.
	conn := make(map[uint64]*Connection, 500)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	ageLim := 10 * time.Minute

	for i := 0; i < numMarshaller; i++ {
		m = append(m, newMarshaller(wg, anon))
	}

	return &Saver{
		Host:         host,
		Pod:          pod,
		FileAgeLimit: ageLim,
		MarshalChans: m,
		Done:         wg,
		Connections:  conn,
		ClosingStats: make(map[uint64]TcpStats, 100),
		cache:        c,
		eventServer:  srv,
		exclude:      ex,
	}
}

// queue queues a single ArchivalRecord to the appropriate marshalling queue, based on the
// connection Cookie.
func (svr *Saver) queue(msg *netlink.ArchivalRecord) error {
	idm, err := msg.RawIDM.Parse()
	if err != nil {
		log.Println(err)
		// TODO error metric
	}
	cookie := idm.ID.Cookie()
	if cookie == 0 {
		return errors.New("Cookie = 0")
	}
	if len(svr.MarshalChans) < 1 {
		return ErrNoMarshallers
	}
	q := svr.MarshalChans[int(cookie%uint64(len(svr.MarshalChans)))]
	conn, ok := svr.Connections[cookie]
	if !ok {
		// Create a new connection for first time cookies.  For late connections already
		// terminating, log some info for debugging purposes.
		if idm.IDiagState >= uint8(tcp.FIN_WAIT1) {
			s, r := msg.GetStats()
			log.Println("Starting:", msg.Timestamp.Format("15:04:05.000"), cookie, tcp.State(idm.IDiagState), TcpStats{s, r})
		}
		conn = newConnection(idm, msg.Timestamp)
		svr.eventServer.FlowCreated(msg.Timestamp, uuid.FromCookie(cookie), idm.ID.GetSockID())
		svr.Connections[cookie] = conn
	} else {
		//log.Println("Diff inode:", inode)
	}
	if time.Now().After(conn.Expiration) && conn.Writer != nil {
		q <- Task{nil, conn.Writer} // Close the previous file.
		conn.Writer = nil
	}
	if conn.Writer == nil {
		err := conn.Rotate(svr.Host, svr.Pod, svr.FileAgeLimit)
		if err != nil {
			return err
		}
	}
	q <- Task{msg, conn.Writer}
	return nil
}

func (svr *Saver) endConn(cookie uint64) {
	svr.eventServer.FlowDeleted(time.Now(), uuid.FromCookie(cookie))
	q := svr.MarshalChans[cookie%uint64(len(svr.MarshalChans))]
	conn, ok := svr.Connections[cookie]
	if ok && conn.Writer != nil {
		q <- Task{nil, conn.Writer}
		delete(svr.Connections, cookie)
	}
}

// Handle a bundle of messages.
// Returns the bytes sent and received on all non-local connections.
func (svr *Saver) handleType(t time.Time, msgs []*netlink.NetlinkMessage) (uint64, uint64) {
	var liveSent, liveReceived uint64
	for _, msg := range msgs {
		// In swap and queue, we want to track the total speed of all connections
		// every second.
		if msg == nil {
			log.Println("Nil message")
			continue
		}
		ar, err := netlink.MakeArchivalRecord(msg, svr.exclude)
		if ar == nil {
			if err != nil {
				log.Println(err)
			}
			continue
		}
		ar.Timestamp = t

		// Note: If GetStats shows up in profiling, might want to move to once/second code.
		s, r := ar.GetStats()
		liveSent += s
		liveReceived += r
		svr.swapAndQueue(ar)
	}

	return liveSent, liveReceived
}

// MessageSaverLoop runs a loop to receive batches of ArchivalRecords.  Local connections
func (svr *Saver) MessageSaverLoop(readerChannel <-chan netlink.MessageBlock) {
	log.Println("Starting Saver")

	var reported, closed TcpStats
	lastReportTime := time.Time{}.Unix()
	closeLogCount := 10000

	for msgs := range readerChannel {

		// Handle v4 and v6 messages, and return the total bytes sent and received.
		// TODO - we only need to collect these stats if this is a reporting cycle.
		// NOTE: Prior to April 2020, we were not using UTC here.  The servers
		// are configured to use UTC time, so this should not make any difference.
		s4, r4 := svr.handleType(msgs.V4Time.UTC(), msgs.V4Messages)
		s6, r6 := svr.handleType(msgs.V6Time.UTC(), msgs.V6Messages)

		// Note that the connections that have closed may have had traffic that
		// we never see, and therefore can't account for in metrics.
		residual := svr.cache.EndCycle()

		// Remove all missing connections from the cache.
		// Also keep a metric of the total cumulative send and receive bytes.
		for cookie := range residual {
			ar := residual[cookie]
			var stats TcpStats
			var ok bool
			if !ar.HasDiagInfo() {
				stats, ok = svr.ClosingStats[cookie]
				if ok {
					// Remove the stats from closing.
					svr.ClosingTotals.Sent -= stats.Sent
					svr.ClosingTotals.Received -= stats.Received
					delete(svr.ClosingStats, cookie)
				} else {
					log.Println("Missing stats for", cookie)
				}
			} else {
				stats.Sent, stats.Received = ar.GetStats()
			}
			closed.Sent += stats.Sent
			closed.Received += stats.Received

			if closeLogCount > 0 {
				idm, err := ar.RawIDM.Parse()
				if err != nil {
					log.Println("Closed:", ar.Timestamp.Format("15:04:05.000"), cookie, "idm parse error", stats)
				} else {
					log.Println("Closed:", ar.Timestamp.Format("15:04:05.000"), cookie, tcp.State(idm.IDiagState), stats)
				}
				closeLogCount--
			}

			svr.endConn(cookie)
			svr.stats.IncExpiredCount()
		}

		// Every second, update the total throughput for the past second.
		if msgs.V4Time.Unix() > lastReportTime {
			// This is the total bytes since program start.
			totalSent := closed.Sent + svr.ClosingTotals.Sent + s4 + s6
			totalReceived := closed.Received + svr.ClosingTotals.Received + r4 + r6

			// NOTE: We are seeing occasions when total < reported.  This messes up prometheus, so
			// we detect that and skip reporting.
			// This seems to be persistent, not just a momentary glitch.  The total may drop by 500KB,
			// and only recover after many seconds of gradual increases (on idle workstation).
			// This workaround seems to also cure the 2<<67 reports.
			// We also check for increments larger than 10x the maxSwitchSpeed.
			// TODO: This can all be discarded when we are confident the bug has been fixed.
			if totalSent > 10*maxSwitchSpeed/8+reported.Sent || totalSent < reported.Sent {
				// Some bug in the accounting!!
				log.Println("Skipping BytesSent report due to bad accounting", totalSent, reported.Sent, closed.Sent, svr.ClosingTotals.Sent, s4, s6)
				if totalSent < reported.Sent {
					metrics.ErrorCount.WithLabelValues("totalSent < reportedSent").Inc()
				} else {
					metrics.ErrorCount.WithLabelValues("totalSent-reportedSent exceeds network capacity").Inc()
				}
			} else {
				metrics.SendRateHistogram.Observe(8 * float64(totalSent-reported.Sent))
				reported.Sent = totalSent // the total bytes reported to prometheus.
			}

			if totalReceived > 10*maxSwitchSpeed/8+reported.Received || totalReceived < reported.Received {
				// Some bug in the accounting!!
				log.Println("Skipping BytesReceived report due to bad accounting", totalReceived, reported.Received, closed.Received, svr.ClosingTotals.Received, r4, r6)
				if totalReceived < reported.Received {
					metrics.ErrorCount.WithLabelValues("totalReceived < reportedReceived").Inc()
				} else {
					metrics.ErrorCount.WithLabelValues("totalReceived-reportedReceived exceeds network capacity").Inc()
				}
			} else {
				metrics.ReceiveRateHistogram.Observe(8 * float64(totalReceived-reported.Received))
				reported.Received = totalReceived // the total bytes reported to prometheus.
			}

			lastReportTime = msgs.V4Time.Unix()
		}
	}
	svr.Close()
}

func (svr *Saver) swapAndQueue(pm *netlink.ArchivalRecord) {
	svr.stats.IncTotalCount() // TODO fix race
	old, err := svr.cache.Update(pm)
	if err != nil {
		// TODO metric
		log.Println(err)
		return
	}
	if old == nil {
		svr.stats.IncNewCount()
		metrics.SnapshotCount.Inc()
		err := svr.queue(pm)
		if err != nil {
			log.Println(err, "Connections", len(svr.Connections))
		}
	} else {
		pmIDM, err := pm.RawIDM.Parse()
		if err != nil {
			// TODO metric
			log.Println(err)
			return
		}
		if !pm.HasDiagInfo() {
			// If the previous record has DiagInfo, store the send/receive stats.
			// We will use them when we close the connection.
			if old.HasDiagInfo() {
				sOld, rOld := old.GetStats()
				svr.ClosingStats[pmIDM.ID.Cookie()] = TcpStats{Sent: sOld, Received: rOld}
				svr.ClosingTotals.Sent += sOld
				svr.ClosingTotals.Received += rOld
				log.Println("Closing:", pm.Timestamp.Format("15:04:05.000"), pmIDM.ID.Cookie(), tcp.State(pmIDM.IDiagState), TcpStats{sOld, rOld})
			}
		}

		change, err := pm.Compare(old)
		if err != nil {
			// TODO metric
			log.Println(err)
			return
		}
		if change > netlink.NoMajorChange {
			svr.stats.IncDiffCount()
			metrics.SnapshotCount.Inc()
			err := svr.queue(pm)
			if err != nil {
				// TODO metric
				log.Println(err)
			}
		}
	}
}

// Close shuts down all the marshallers, and waits for all files to be closed.
func (svr *Saver) Close() {
	log.Println("Terminating Saver")
	log.Println("Total of", len(svr.Connections), "connections active.")
	for i := range svr.Connections {
		svr.endConn(i)
	}
	log.Println("Closing Marshallers")
	for i := range svr.MarshalChans {
		close(svr.MarshalChans[i])
	}
	svr.Done.Done()
}

// LogCacheStats prints out some basic cache stats.
// TODO(https://github.com/m-lab/tcp-info/issues/32) - should also export all of these as Prometheus metrics.
func (svr *Saver) LogCacheStats(localCount, errCount int) {
	stats := svr.stats.Copy() // Get a copy
	log.Printf("Cache info total %d  local %d same %d diff %d new %d err %d\n",
		stats.TotalCount+(int64)(localCount), localCount,
		stats.TotalCount-((int64)(errCount)+stats.NewCount+stats.DiffCount+(int64)(localCount)),
		stats.DiffCount, stats.NewCount, errCount)
}
