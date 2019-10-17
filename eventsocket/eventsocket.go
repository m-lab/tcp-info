package eventsocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
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
// clients. The UUID, Timestamp, and Event fields are required, all other fields
// are optional.
type FlowEvent struct {
	Event        TCPEvent
	Timestamp    time.Time
	Src, Dest    string `json:",omitempty"`
	SPort, DPort uint16 `json:",omitempty"`
	UUID         string
}

// Server is the struct that has the methods that actually serve the events over
// the unix domain socket. You should make new Server objects with
// eventsocket.New unless you really know what you are doing (e.g. you are
// writing unit tests).
type Server struct {
	eventC       chan *FlowEvent
	filename     string
	clients      map[net.Conn]struct{}
	unixListener net.Listener
	mutex        sync.Mutex
	servingWG    sync.WaitGroup
}

func (s *Server) addClient(c net.Conn) {
	log.Println("Adding new TCP event client", c)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clients[c] = struct{}{}
}

func (s *Server) removeClient(c net.Conn) {
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

func (s *Server) sendToAllListeners(data string) {
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

func (s *Server) notifyClients(ctx context.Context) {
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
func (s *Server) Listen() error {
	// Add to the waitgroup inside Listen(), subtract from it in Serve(). That way,
	// even if the Serve() goroutine is scheduled weirdly, servingWG.Wait() will
	// definitely wait for Serve() to finish.
	s.servingWG.Add(1)
	var err error
	s.unixListener, err = net.Listen("unix", s.filename)
	return err
}

// Serve all clients that connect to this server until the context is canceled.
// It is expected that this will be called in a goroutine, after Listen has been
// called.  This function should only be called once for a given server.
func (s *Server) Serve(ctx context.Context) error {
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
			break
		}
		s.addClient(conn)
	}
	return err
}

// FlowCreated should be called whenever tcpinfo notices a new flow is created.
func (s *Server) FlowCreated(src, dest string, sport, dport uint16, uuid string) {
	s.eventC <- &FlowEvent{
		Event:     Open,
		Timestamp: time.Now(),
		Src:       src,
		Dest:      dest,
		SPort:     sport,
		DPort:     dport,
		UUID:      uuid,
	}
}

// FlowDeleted should be called whenever tcpinfo notices a flow has been retired.
func (s *Server) FlowDeleted(uuid string) {
	s.eventC <- &FlowEvent{
		Event:     Close,
		Timestamp: time.Now(),
		UUID:      uuid,
	}
}

// New makes a new server that serves clients on the provided Unix domain socket.
func New(filename string) *Server {
	c := make(chan *FlowEvent, 100)
	return &Server{
		filename: filename,
		eventC:   c,
		clients:  make(map[net.Conn]struct{}),
	}
}
