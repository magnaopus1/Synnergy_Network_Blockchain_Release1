package crosschain

import (
	"crypto/tls"
	"net"
	"time"
)

// StandardProtocol defines the interface for cross-chain communication protocols.
type StandardProtocol interface {
	Connect(peer string) (net.Conn, error)
	Send(conn net.Conn, data []byte) error
	Receive(conn net.Conn) ([]byte, error)
	Close(conn net.Conn) error
}

// TCPProtocol implements the StandardProtocol interface using TCP.
type TCPProtocol struct {
	config *tls.Config
}

// NewTCPProtocol creates a new TCPProtocol with TLS configuration.
func NewTCPProtocol(certFile, keyFile string) (*TCPProtocol, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return &TCPProtocol{config: config}, nil
}

// Connect establishes a secure TCP connection to the specified peer.
func (t *TCPProtocol) Connect(peer string) (net.Conn, error) {
	return tls.Dial("tcp", peer, t.config)
}

// Send transmits data over the established TCP connection.
func (t *TCPProtocol) Send(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

// Receive reads data from the established TCP connection.
func (t *TCPProtocol) Receive(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

// Close terminates the TCP connection.
func (t *TCPProtocol) Close(conn net.Conn) error {
	return conn.Close()
}

// Example usage
func main() {
	// Setup secure protocol
	protocol, err := NewTCPProtocol("path/to/cert.pem", "path/to/key.pem")
	if err != nil {
		panic(err)
	}

	// Connect to a peer
	conn, err := protocol.Connect("peer.address:port")
	if err != nil {
		panic(err)
	}
	defer protocol.Close(conn)

	// Send data
	message := []byte("Hello, Blockchain World!")
	if err := protocol.Send(conn, message); err != nil {
		panic(err)
	}

	// Receive data
	response, err := protocol.Receive(conn)
	if err != nil {
		panic(err)
	}

	// Process response
	println(string(response))
}
