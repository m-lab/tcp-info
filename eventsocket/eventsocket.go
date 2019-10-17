package eventsocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
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
// clients. The UUID and Event fields are required, all other fields are
// optional.
type FlowEvent struct {
	Event        TCPEvent
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
	listeners    map[net.Conn]struct{}
	unixListener net.Listener
	mutex        sync.Mutex
}

func (s *Server) addListener(c net.Conn) {
	log.Println("Adding listener", c)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.listeners[c] = struct{}{}
}

func (s *Server) removeListener(c net.Conn) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.listeners[c]
	if !ok {
		log.Println("Tried to remove listener", c, "that was not present")
		return
	}
	delete(s.listeners, c)
}

func (s *Server) sendToAllListeners(data string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for c := range s.listeners {
		_, err := fmt.Fprintln(c, data)
		if err != nil {
			log.Println("Write to listener", c, "failed with error", err, " - removing the listener.")
			// Remove in a goroutine because removeListener needs to grab the
			// mutex, so let the goroutine block until the mutex is released
			// when this method returns. This also prevents mid-iteration
			// modification of s.listeners.
			go s.removeListener(c)
		}
	}
}

func (s *Server) notifyListeners(ctx context.Context) {
	for ctx.Err() == nil {
		event := <-s.eventC
		log.Println("Muxing event")
		var b []byte
		var err error
		if event != nil {
			b, err = json.Marshal(*event)
		}
		log.Println("Got event!")
		if event == nil || err != nil {
			log.Printf("WARNING: Bad event received %v\n", event)
			continue
		}
		s.sendToAllListeners(string(b))
	}
}

// Listen returns quickly. After Listen has been called, connections to the
// server will not immediately fail. In order for them to succeed, Serve()
// should be called.
func (s *Server) Listen() error {
	var err error
	s.unixListener, err = net.Listen("unix", s.filename)
	return err
}

// Serve all clients that connect to this server until the context is canceled.
// It is expected that this will be called in a goroutine, after Listen has been
// called.
func (s *Server) Serve(ctx context.Context) error {
	derivedCtx, derivedCancel := context.WithCancel(ctx)
	defer derivedCancel()

	go s.notifyListeners(derivedCtx)

	// When the context is canceled, close the listener
	go func() {
		<-derivedCtx.Done()
		s.unixListener.Close()
	}()

	var err error
	for derivedCtx.Err() == nil {
		var conn net.Conn
		conn, err = s.unixListener.Accept()
		if err != nil {
			log.Printf("Could not Accept on socket %q: %s\n", s.filename, err)
			break
		}
		s.addListener(conn)
	}
	return err
}

// FlowCreated should be called whenever tcpinfo notices a new flow is created.
func (s *Server) FlowCreated(src, dest string, sport, dport uint16, uuid string) {
	s.eventC <- &FlowEvent{
		Event: Open,
		Src:   src,
		Dest:  dest,
		SPort: sport,
		DPort: dport,
		UUID:  uuid,
	}
}

// FlowDeleted should be called whenever tcpinfo notices a flow has been retired.
func (s *Server) FlowDeleted(uuid string) {
	log.Println("Flow deletion event:", uuid)
	s.eventC <- &FlowEvent{
		Event: Close,
		UUID:  uuid,
	}
}

// New makes a new server that serves clients on the provided Unix domain socket.
func New(filename string) *Server {
	c := make(chan *FlowEvent, 100)
	return &Server{
		filename:  filename,
		eventC:    c,
		listeners: make(map[net.Conn]struct{}),
	}
}
