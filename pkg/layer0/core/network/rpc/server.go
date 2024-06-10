package rpc

import (
	"net"
	"net/rpc"
	"log"
	"crypto/tls"
	"github.com/synthron_blockchain_final/pkg/layer0/core/network/security"
)

// RPCServer encapsulates the RPC server functionalities.
type RPCServer struct {
	Address  string          // Server address
	Security security.Config // Security configuration
}

// NewRPCServer initializes a new RPC server given an address and security configuration.
func NewRPCServer(address string, config security.Config) *RPCServer {
	return &RPCServer{
		Address:  address,
		Security: config,
	}
}

// Start initializes and starts the RPC server, listening for incoming requests.
func (s *RPCServer) Start() {
	// Setup the RPC server
	server := rpc.NewServer()
	rpchandle := NewRPCHandler() // Assume NewRPCHandler initializes your RPC methods
	server.Register(rpchandle)

	// Create listener with TLS for secure communication
	config := &tls.Config{
		Certificates: []tls.Certificate{s.Security.TLSCertificate},
	}
	listener, err := tls.Listen("tcp", s.Address, config)
	if err != nil {
		log.Fatalf("Unable to start RPC server: %v", err)
	}
	log.Printf("RPC Server listening on %s", s.Address)

	// Accept connections
	go s.acceptConnections(server, listener)
}

// acceptConnections handles incoming connections in a separate goroutine.
func (s *RPCServer) acceptConnection(server *rpc.Server, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		go server.ServeConn(conn)
	}
}

// Stop gracefully shuts down the server.
func (s *RPCServer) Stop(listener net.Listener) {
	if err := listener.Close(); err != nil {
		log.Printf("Failed to close listener: %v", err)
	}
	log.Println("RPC Server stopped")
}

// Implement additional helper methods if necessary, such as for security checks, logging, etc.

