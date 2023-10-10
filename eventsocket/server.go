package eventsocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/m-lab/tcp-info/inetdiag"
	"github.com/m-lab/tcp-info/metrics"
)

//go:generate stringer -type=TCPEvent

// TCPEvent refers to the kind of socket event that has occurred. Right now, we
// support Open and Close events, but it is not impossible to imagine future
// versions that do more.
type TCPEvent int

const (
	// Open is sent when a TCP connection is created.
	Open = TCPEvent(iota)
	// Close is sent when a TCP connection is closed.
	Close
)

// FlowEvent is the data that is sent down the socket in JSONL form to the
// clients. The UUID, Timestamp, and Event fields will always be filled in, all
// other fields are optional.
type FlowEvent struct {
	Event     TCPEvent
	Timestamp time.Time
	UUID      string
	ID        *inetdiag.SockID //`json:",omitempty"`
}

// Server is the interface that has the methods that actually serve the events
// over the unix domain socket. You should make new Server objects with
// eventsocket.New or eventsocket.NullServer.
type Server interface {
	Listen() error
	Serve(context.Context) error
	FlowCreated(timestamp time.Time, uuid string, sockid inetdiag.SockID)
	FlowDeleted(timestamp time.Time, uuid string)
}

type server struct {
	eventC       chan *FlowEvent
	filename     string
	clients      map[net.Conn]struct{}
	unixListener net.Listener
	mutex        sync.Mutex
	servingWG    sync.WaitGroup
}

func (s *server) addClient(c net.Conn) {
	log.Println("Adding new TCP event client", c)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clients[c] = struct{}{}
}

func (s *server) removeClient(c net.Conn) {
	s.servingWG.Add(1)
	defer s.servingWG.Done()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.clients[c]
	if !ok {
		log.Println("Tried to remove TCP event client", c, "that was not present")
		return
	}
	delete(s.clients, c)
}

func (s *server) sendToAllListeners(data string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for c := range s.clients {
		_, err := fmt.Fprintln(c, data)
		if err != nil {
			log.Println("Write to client", c, "failed with error", err, " - removing the client.")
			// Remove in a goroutine because removeClient needs to grab the
			// mutex, so let the goroutine block until the mutex is released
			// when this method returns. This also prevents mid-iteration
			// modification of s.clients.
			go s.removeClient(c)
			go c.Close()
		}
	}
}

func (s *server) notifyClients(ctx context.Context) {
	s.servingWG.Add(1)
	defer s.servingWG.Done()
	for ctx.Err() == nil {
		event := <-s.eventC
		var b []byte
		var err error
		if event != nil {
			b, err = json.Marshal(*event)
		}
		if event == nil || err != nil {
			log.Printf("WARNING: Bad event received %v (err: %v)\n", event, err)
			continue
		}
		s.sendToAllListeners(string(b))
	}
}

// Listen returns quickly. After Listen has been called, connections to the
// server will not immediately fail. In order for them to succeed, Serve()
// should be called. This function should only be called once for a given
// Server.
func (s *server) Listen() error {
	// Add to the waitgroup inside Listen(), subtract from it in Serve(). That way,
	// even if the Serve() goroutine is scheduled weirdly, servingWG.Wait() will
	// definitely wait for Serve() to finish.
	s.servingWG.Add(1)
	var err error
	// Delete any existing socket file before trying to listen on it. Unclean
	// shutdowns can cause orphaned, stale socket files to hang around, causing
	// this service to fail to start because it can't create the socket.
	os.Remove(s.filename)
	s.unixListener, err = net.Listen("unix", s.filename)
	return err
}

// Serve all clients that connect to this server until the context is canceled.
// It is expected that this will be called in a goroutine, after Listen has been
// called.  This function should only be called once for a given server.
func (s *server) Serve(ctx context.Context) error {
	defer s.servingWG.Done()
	derivedCtx, derivedCancel := context.WithCancel(ctx)
	defer derivedCancel()

	go s.notifyClients(derivedCtx)

	// When the context is canceled (which happens when this function exits, but
	// could happen sooner if the parent context is canceled), close the
	// listener and the internal channel. These two closes, along with the
	// context cancellation, should cause every other goroutine to terminate.
	s.servingWG.Add(1) // Add this cleanup goroutine to the waitgroup.
	go func() {
		<-derivedCtx.Done()
		s.unixListener.Close()
		close(s.eventC)
		s.servingWG.Done()
	}()

	var err error
	for derivedCtx.Err() == nil {
		var conn net.Conn
		conn, err = s.unixListener.Accept()
		if err != nil {
			log.Printf("Could not Accept on socket %q: %s\n", s.filename, err)
			continue
		}
		s.addClient(conn)
	}
	return err
}

// FlowCreated should be called whenever tcpinfo notices a new flow is created.
func (s *server) FlowCreated(timestamp time.Time, uuid string, id inetdiag.SockID) {
	s.eventC <- &FlowEvent{
		Event:     Open,
		Timestamp: timestamp,
		ID:        &id,
		UUID:      uuid,
	}
	metrics.FlowEventsCounter.WithLabelValues("open").Inc()
}

// FlowDeleted should be called whenever tcpinfo notices a flow has been retired.
func (s *server) FlowDeleted(timestamp time.Time, uuid string) {
	s.eventC <- &FlowEvent{
		Event:     Close,
		Timestamp: timestamp,
		UUID:      uuid,
	}
}

// New makes a new server that serves clients on the provided Unix domain socket.
func New(filename string) Server {
	c := make(chan *FlowEvent, 100)
	return &server{
		filename: filename,
		eventC:   c,
		clients:  make(map[net.Conn]struct{}),
	}
}

type nullServer struct{}

// Empty implementations that do no harm.
func (nullServer) Listen() error                                                    { return nil }
func (nullServer) Serve(context.Context) error                                      { return nil }
func (nullServer) FlowCreated(timestamp time.Time, uuid string, id inetdiag.SockID) {}
func (nullServer) FlowDeleted(timestamp time.Time, uuid string)                     {}

// NullServer returns a Server that does nothing. It is made so that code that
// may or may not want to use a eventsocket can receive a Server interface and
// not have to worry about whether it is nil.
func NullServer() Server {
	return nullServer{}
}
