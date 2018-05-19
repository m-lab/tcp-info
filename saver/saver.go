// Package saver contains all logic for writing records to files.
package saver

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/m-lab/tcp-info/cache"
	"github.com/m-lab/tcp-info/inetdiag"
	tcp "github.com/m-lab/tcp-info/nl-proto"
	"github.com/m-lab/tcp-info/nl-proto/tools"
	"github.com/m-lab/tcp-info/zstd"
)

// We will send an entire batch of NetlinkMessages through a channel from
// the collection loop to the top level saver.  The saver will sort and
// discard any local connection, maintain the connection cache, determine
// how frequently to save deltas for each connection.
//
// The saver will use a small set of Marshallers to convert to protos,
// marshal the protos, and write them to files.

// KEY QUESTION:
//  should files contain a single connection, or interleaved records from
//  many connections?  Perhaps a single file for a set of connections to
//  a single apparent client IP?
// Keep it simple.  One (or more) files per connection.

// This module handles writing records to appropriate files, and cycling
// the files when they are too large, or open for more than 60 minutes.

// 1.  Map from local address to file family.
// 2.  Map from file family to current file.
// 3.  Map from inode to active file.
//
// QUESTIONS:
//  Should each connection have its own file?  PROBABLY!
//  Should local address be encoded in the file name?
//  Should we use the same file naming convention as current sidestream?

//  Other design elements:

type Task struct {
	// nil message means close the writer.
	Message *inetdiag.ParsedMessage
	Writer  io.WriteCloser
}

type Marshaller chan<- Task

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
		msg := task.Message
		pb := tools.CreateProto(msg.Header, msg.InetDiagMsg, msg.Attributes[:])
		wire, err := proto.Marshal(pb)
		if err != nil {
			log.Println(err)
		} else {
			task.Writer.Write(wire)
		}
	}
	log.Println("Marshaller Done")
	wg.Done()
}

func NewMarshaller(wg *sync.WaitGroup) Marshaller {
	marshChan := make(chan Task, 100)
	wg.Add(1)
	go runMarshaller(marshChan, wg)
	return marshChan
}

// Connection objects handle all output associated with a single connection.
type Connection struct {
	Inode      uint32 // TODO - also use the UID???
	ID         inetdiag.InetDiagSockID
	Slice      string    // 4 hex, indicating which machine segment this is on.
	StartTime  time.Time // Time the connection was initiated.
	Sequence   int       // Typically zero, but increments for long running connections.
	Expiration time.Time // Time we will swap files and increment Sequence.
	Writer     io.WriteCloser
}

func NewConnection(info *inetdiag.InetDiagMsg) *Connection {
	conn := Connection{Inode: info.IDiagInode, ID: info.ID, Slice: "", StartTime: time.Now(), Sequence: 0,
		Expiration: time.Now()}
	return &conn
}

// Rotate closes an existing writer, and opens a new one.
func (conn *Connection) Rotate(Host string, Pod string, FileAgeLimit time.Duration) {
	// Use ID info from msg to create filename.
	conn.Sequence++
	// 2006-01-02 15:04:05.999999999
	date := conn.StartTime.Format("20160102Z150405.999")
	conn.Writer = zstd.NewWriter(fmt.Sprintf("%s-%d-%d.zstd", date, conn.Inode, conn.Sequence))
	conn.Expiration = conn.Expiration.Add(10 * time.Minute)
}

type Saver struct {
	Host         string // mlabN
	Pod          string // 3 alpha + 2 decimal
	FileAgeLimit time.Duration
	Marshallers  []Marshaller
	Done         *sync.WaitGroup // All marshallers will call Done on this.
	Connections  map[uint32]*Connection

	cache        *cache.Cache
	totalCount   int
	newCount     int
	diffCount    int
	expiredCount int
}

func NewSaver(host string, pod string, numMarshaller int) *Saver {
	m := make([]Marshaller, 0, numMarshaller)
	c := cache.NewCache()
	conn := make(map[uint32]*Connection, 500)
	wg := &sync.WaitGroup{}
	ageLim := 10 * time.Minute

	for i := 0; i < numMarshaller; i++ {
		m = append(m, NewMarshaller(wg))
	}
	return &Saver{Host: host, Pod: pod, FileAgeLimit: ageLim, Marshallers: m, Done: wg, Connections: conn, cache: c}
}

func (svr *Saver) Queue(msg *inetdiag.ParsedMessage) {
	//log.Println(msg.InetDiagMsg)
	inode := msg.InetDiagMsg.IDiagInode
	if inode == 0 {
		if msg.InetDiagMsg.IDiagState != uint8(tcp.TCPState_FIN_WAIT2) {
			log.Println("BAD:", msg.InetDiagMsg)
		}
		// TODO - FIN_WAIT2 doesn't have an inode!!
		return
	}
	if len(svr.Marshallers) < 1 {
		log.Fatal("Fatal: no marshallers")
	}
	q := svr.Marshallers[int(inode)%len(svr.Marshallers)]
	conn, ok := svr.Connections[inode]
	if !ok {
		log.Println("New inode:", inode)
		conn = NewConnection(msg.InetDiagMsg)
		svr.Connections[inode] = conn
	} else {
		//log.Println("Diff inode:", inode)
	}
	if time.Now().After(conn.Expiration) && conn.Writer != nil {
		q <- Task{nil, conn.Writer} // Close the previous file.
		conn.Writer = nil
	}
	if conn.Writer == nil {
		conn.Rotate(svr.Host, svr.Pod, svr.FileAgeLimit)
	}
	q <- Task{msg, conn.Writer}
}

func (svr *Saver) EndConn(inode uint32) {
	q := svr.Marshallers[int(inode)%len(svr.Marshallers)]
	conn, ok := svr.Connections[inode]
	if ok && conn.Writer != nil {
		q <- Task{nil, conn.Writer}
		delete(svr.Connections, inode)
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
				svr.EndConn(residual[i].InetDiagMsg.IDiagInode)
				svr.expiredCount++
			}
		}
		log.Println("Terminating Saver")
		for i := range svr.Connections {
			svr.EndConn(i)
		}
		log.Println("Closing Marshallers")
		for i := range svr.Marshallers {
			close(svr.Marshallers[i])
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
		svr.Queue(pm)
	} else {
		if tools.Compare(pm, old) > tools.NoMajorChange {
			svr.diffCount++
			svr.Queue(pm)
		}
	}
}
