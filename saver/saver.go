// Package saver contains all logic for writing records to files.
//  1. Sets up a channel that accepts slices of *inetdiag.ParsedMessage
//  2. Maintains a map of Connections, one for each connection.
//  3. Uses several marshallers goroutines to convert to protobufs and write to
//     zstd files.
//  4. Rotates Connection output files every 10 minutes for long lasting connections.
//  5. uses a cache to detect meaningful state changes, and avoid excessive
//     writes.
package saver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
	tcp "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/nl-proto/tools"
	"github.com/m-lab/tcp-info/zstd"
)

// We will send an entire batch of prefiltered ParsedMessages through a channel from
// the collection loop to the top level saver.  The saver will detect new connections
// and significant diffs, maintain the connection cache, determine
// how frequently to save deltas for each connection.
//
// The saver will use a small set of Marshallers to convert to protos,
// marshal the protos, and write them to files.

// Tests:
//   Basic marshaller test.  Simulated data.  Checks filename and size, cleans up.
//   File closing.
//   Marshaller selection.
//   Rotation  (use 1 second rotation time)

type Task struct {
	// nil message means close the writer.
	Message *inetdiag.ParsedMessage
	Writer  io.WriteCloser
}

type MarshalChan chan<- Task

func runMarshaller(taskChan <-chan Task, wg *sync.WaitGroup) {
	for {
		task, ok := <-taskChan
		if !ok {
			break
		}
		if task.Message == nil {
			task.Writer.Close()
			continue
		}
		if task.Writer == nil {
			log.Fatal("Nil writer")
		}
		msg := task.Message
		pb := tools.CreateProto(msg.Timestamp, msg.Header, msg.InetDiagMsg, msg.Attributes[:])
		wire, err := proto.Marshal(pb)
		if err != nil {
			log.Println(err)
		} else {
			// For each record, write the size of the record, followed by the record itself.
			size := make([]byte, 9)
			lsize := binary.PutUvarint(size, uint64(len(wire))) // task.Writer
			_, err = task.Writer.Write(size[:lsize])
			if err != nil {
				log.Println(err)
			}
			_, err = task.Writer.Write(wire)
			if err != nil {
				log.Println(err)
			}
		}
	}
	log.Println("Marshaller Done")
	wg.Done()
}

func NewMarshaller(wg *sync.WaitGroup) MarshalChan {
	marshChan := make(chan Task, 100)
	wg.Add(1)
	go runMarshaller(marshChan, wg)
	return marshChan
}

// Connection objects handle all output associated with a single connection.
type Connection struct {
	Inode      uint32 // TODO - also use the UID???
	ID         inetdiag.InetDiagSockID
	UID        uint32
	Slice      string    // 4 hex, indicating which machine segment this is on.
	StartTime  time.Time // Time the connection was initiated.
	Sequence   int       // Typically zero, but increments for long running connections.
	Expiration time.Time // Time we will swap files and increment Sequence.
	Writer     io.WriteCloser
}

func NewConnection(info *inetdiag.InetDiagMsg, timestamp time.Time) *Connection {
	conn := Connection{Inode: info.IDiagInode, ID: info.ID, UID: info.IDiagUID, Slice: "", StartTime: timestamp, Sequence: 0,
		Expiration: time.Now()}
	return &conn
}

// Rotate opens the next writer for a connection.
func (conn *Connection) Rotate(Host string, Pod string, FileAgeLimit time.Duration) error {
	date := conn.StartTime.Format("20060102Z150405.000")
	id := fmt.Sprintf("L%s:%dR%s:%d", conn.ID.SrcIP(), conn.ID.SPort(), conn.ID.DstIP(), conn.ID.DPort())
	var err error
	conn.Writer, err = zstd.NewWriter(fmt.Sprintf("%sU%08d%s_%05d.zst", date, conn.UID, id, conn.Sequence))
	if err != nil {
		return err
	}
	metrics.FileCount.Inc()
	conn.Expiration = conn.Expiration.Add(10 * time.Minute)
	conn.Sequence++
	return nil
}

type Saver struct {
	Host         string // mlabN
	Pod          string // 3 alpha + 2 decimal
	FileAgeLimit time.Duration
	MarshalChans []MarshalChan
	Done         *sync.WaitGroup // All marshallers will call Done on this.
	Connections  map[uint64]*Connection

	cache        *cache.Cache
	totalCount   int
	newCount     int
	diffCount    int
	expiredCount int
}

func NewSaver(host string, pod string, numMarshaller int) *Saver {
	m := make([]MarshalChan, 0, numMarshaller)
	c := cache.NewCache()
	conn := make(map[uint64]*Connection, 500)
	wg := &sync.WaitGroup{}
	ageLim := 10 * time.Minute

	for i := 0; i < numMarshaller; i++ {
		m = append(m, NewMarshaller(wg))
	}
	return &Saver{Host: host, Pod: pod, FileAgeLimit: ageLim, MarshalChans: m, Done: wg, Connections: conn, cache: c}
}

var cachePrimed = false

func (svr *Saver) Queue(msg *inetdiag.ParsedMessage) error {
	cookie := msg.InetDiagMsg.ID.Cookie()
	if cookie == 0 {
		return errors.New("Cookie = 0")
	}
	if len(svr.MarshalChans) < 1 {
		log.Fatal("Fatal: no marshallers")
	}
	q := svr.MarshalChans[int(cookie%uint64(len(svr.MarshalChans)))]
	conn, ok := svr.Connections[cookie]
	if !ok {
		// Likely first time we have seen this connection.  Create a new Connection, unless
		// the connection is already closing.
		if msg.InetDiagMsg.IDiagState >= uint8(tcp.TCPState_FIN_WAIT1) {
			log.Println("Skipping", msg.InetDiagMsg, msg.Timestamp)
			return nil
		}
		if cachePrimed || msg.InetDiagMsg.IDiagState != uint8(tcp.TCPState_ESTABLISHED) {
			log.Println("New conn:", msg.InetDiagMsg, msg.Timestamp)
		}
		conn = NewConnection(msg.InetDiagMsg, msg.Timestamp)
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

func (svr *Saver) EndConn(cookie uint64) {
	//log.Println("Closing:", cookie)
	q := svr.MarshalChans[cookie%uint64(len(svr.MarshalChans))]
	conn, ok := svr.Connections[cookie]
	if ok && conn.Writer != nil {
		q <- Task{nil, conn.Writer}
		delete(svr.Connections, cookie)
	}
}

// RunSaverLoop runs a loop to receive batches of ParsedMessages.  Local connections
// should be already stripped out.
func (svr *Saver) RunSaverLoop() chan<- []*inetdiag.ParsedMessage {
	groupChan := make(chan []*inetdiag.ParsedMessage, 2)
	go func() {
		log.Println("Starting Saver")
		for {
			group, ok := <-groupChan
			if !ok {
				break
			}

			for i := range group {
				if group[i] == nil {
					log.Println("Error")
					continue
				}
				svr.SwapAndQueue(group[i])
			}
			residual := svr.cache.EndCycle()

			for i := range residual {
				svr.EndConn(residual[i].InetDiagMsg.ID.Cookie())
				svr.expiredCount++
			}

			cachePrimed = true
		}
		log.Println("Terminating Saver")
		log.Println("Total of", len(svr.Connections), "connections active.")
		for i := range svr.Connections {
			svr.EndConn(i)
		}
		log.Println("Closing Marshallers")
		for i := range svr.MarshalChans {
			close(svr.MarshalChans[i])
		}
		svr.Stats()
		svr.Done.Wait()
	}()
	return groupChan
}

func (svr *Saver) Stats() {
	log.Printf("Cache info total %d same %d diff %d new %d closed %d\n",
		svr.totalCount, svr.totalCount-(svr.newCount+svr.diffCount),
		svr.diffCount, svr.newCount, svr.expiredCount)
}

func (svr *Saver) SwapAndQueue(pm *inetdiag.ParsedMessage) {
	svr.totalCount++
	old := svr.cache.Update(pm)
	if old == nil {
		svr.newCount++
		err := svr.Queue(pm)
		if err != nil {
			log.Println(err)
			log.Println("Connections", len(svr.Connections))
		}
	} else {
		if old.InetDiagMsg.ID != pm.InetDiagMsg.ID {
			log.Println("Mismatched SockIDs", old.InetDiagMsg.ID, pm.InetDiagMsg.ID)
		}
		if tools.Compare(pm, old) > tools.NoMajorChange {
			svr.diffCount++
			err := svr.Queue(pm)
			if err != nil {
				log.Println(err)
			}
		}
	}
}