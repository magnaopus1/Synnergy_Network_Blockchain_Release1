package network

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	"github.com/multiformats/go-multiaddr"
)

// TransportLayer handles establishing and managing network connections.
type TransportLayer struct {
	host.Host
}

// NewTransportLayer creates a new transport layer with TLS encryption.
func NewTransportLayer(ctx context.Context, listenAddr string, priv crypto.PrivKey) (*TransportLayer, error) {
	addr, err := multiaddr.NewMultiaddr(listenAddr)
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(ctx,
		libp2p.ListenAddrs(addr),
		libp2p.Identity(priv),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
	)
	if err != nil {
		return nil, err
	}

	return &TransportLayer{Host: h}, nil
}

// ConnectToPeer establishes a secure connection to a peer.
func (t *TransportLayer) ConnectToPeer(ctx context.Context, peerAddr string) error {
	peerInfo, err := peer.AddrInfoFromString(peerAddr)
	if err != nil {
		return err
	}

	err = t.Connect(ctx, *peerInfo)
	if err != nil {
		log.Printf("Failed to connect to peer %s: %v", peerInfo.ID, err)
		return err
	}
	log.Printf("Successfully connected to peer %s", peerInfo.ID)
	return nil
}

// StartListening begins listening for incoming connections.
func (t *TransportLayer) StartListening() {
	log.Println("Starting network listener...")
	select {}
}

// SetupTLS configures the host with TLS security.
func (t *TransportLayer) SetupTLS(cert tls.Certificate) error {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	listener, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Println("TLS listener started. Waiting for connections...")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go t.handleTLSConnection(conn)
	}
}

func (t *TransportLayer) handleTLSConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Handling new connection from %s", conn.RemoteAddr().String())

	// Example handling logic
	buffer := make([]byte, 1024)
	_, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	log.Printf("Received data: %s", string(buffer))
}

func main() {
	ctx := context.Background()
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1) // Key generation for example purposes

	transport, err := NewTransportLayer(ctx, "/ip4/0.0.0.0/tcp/4001", priv)
	if err != nil {
		log.Fatalf("Failed to create transport layer: %v", err)
	}

	// Example TLS certificate setup, in real scenarios load from secure storage
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	_ = transport.SetupTLS(cert) // Set up TLS with the loaded certificate

	go transport.StartListening() // Start listening indefinitely
	select {}                     // Run indefinitely
}
