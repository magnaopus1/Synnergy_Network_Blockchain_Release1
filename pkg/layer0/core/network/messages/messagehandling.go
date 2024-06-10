package messages

import (
	"bytes"
	"encoding/gob"
	"log"
	"net"
	"sync"

	"google.golang.org/protobuf/proto"
)

// Message represents a generic structure for network messages.
type Message struct {
	Type    string
	Payload []byte
}

// Handler defines the interface for message processing.
type Handler interface {
	HandleMessage(msg Message) error
}

// Server represents the network server for handling messages.
type Server struct {
	listener net.Listener
	handler  Handler
}

// NewServer creates a new message handling server.
func NewServer(address string, handler Handler) (*Server, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &Server{
		listener: l,
		handler:  handler,
	}, nil
}

// Start runs the server to accept and process messages.
func (s *Server) Start() {
	defer s.listener.Close()
	var wg sync.WaitGroup
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConnection(conn)
		}()
	}
	wg.Wait()
}

// handleConnection handles individual TCP connections.
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	var msg Message
	dec := gob.NewDecoder(conn)
	if err := dec.Decode(&msg); err != nil {
		log.Printf("Failed to decode message: %v", err)
		return
	}

	if err := s.handler.HandleMessage(msg); err != nil {
		log.Printf("Failed to handle message: %v", err)
		// Optionally send an error message back to the sender
	}
}

// handleMessageExample is an example implementation of a message handler.
type handleMessageExample struct{}

// HandleMessage processes the received message.
func (h *handleMessageex) HandleMessage(msg Message) error {
	// Process the message
	log.Printf("Received message: %v", msg)
	return nil
}

// Example of starting the server
func main() {
	handler := &handleMessageExample{}
	server, err := NewServer("localhost:8080", handler)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	server.Start()
}
