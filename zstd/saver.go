package zstd

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/nl-proto/tools"
)

// We will send an entire batch of NetlinkMessages through a channel from
// the collection loop to the recorder.
// The recorder will then dispatch individual records to appropriate
// asynchronous Marshallers.

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

type MachineConfig struct {
	Host string // mlabN
	Pod  string // 3 alpha + 2 decimal
}

type Marshaller struct {
	Send chan<- *inetdiag.ParsedMessage
	Done <-chan struct{} // Or should this be a WaitGroup?
}

// Connection objects handle all output associated with a single connection.
type Connection struct {
	Inode      uint32
	Slice      string     // 4 hex, indicating which machine segment this is on.
	StartTime  time.Time  // Time the connection was initiated.
	Sequence   int        // Typically zero, but increments for long running connections.
	Expiration time.Time  // Time we will swap files and increment Sequence.
	Handler    Marshaller // Cuurent output channel
}

func NewConnection() Connection {

	return Connection{}
}

type FileMapper struct {
	FileAgeLimit time.Duration
	Connections  map[uint32]Connection
}

func Marshal(filename string, marshaler chan *inetdiag.ParsedMessage, wg *sync.WaitGroup) {
	out, pipeWg := NewWriter(filename)
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

func NewMarshaller() {
	marshChan := make(chan *inetdiag.ParsedMessage, 1000)
	marshallerChannels = append(marshallerChannels, marshChan)
	fn := fmt.Sprintf("file%02d.zst", i)
	wg.Add(1)
	go Marshal(fn, marshChan, &wg)
}
