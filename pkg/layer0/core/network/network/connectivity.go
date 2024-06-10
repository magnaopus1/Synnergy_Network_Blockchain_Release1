package network

import (
	"crypto/tls"
	"log"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/multiformats/go-multiaddr"
)

// NetworkNode represents a node within the Synnergy Network.
type NetworkNode struct {
	host.Host
	peers []peer.AddrInfo
}

// NewNetworkNode initializes a new network node with given configuration.
func NewNetworkNode(listenAddr string, privateKey crypto.PrivKey, psk pnet.PSK) (*NetworkNode, error) {
	listener, err := multiaddr.NewMultiaddr(listenAddr)
	if err != nil {
		return nil, err
	}

	options := []libp2p.Option{
		libp2p.ListenAddrs(listener),
		libp2p.Identity(privateKey),
		libp2p.PrivateNetwork(psk),
		libp2p.DefaultSecurity,
	}

	h, err := libp2p.New(options...)
	if err != nil {
		return nil, err
	}

	return &NetworkNode{Host: h}, nil
}

// ConnectPeers establishes connections to known peers in the network.
func (n *NetworkNode) ConnectPeers() error {
	var wg sync.WaitGroup
	for _, p := range n.peers {
		wg.Add(1)
		go func(peerInfo peer.AddrInfo) {
			defer wg.Done()
			if err := n.Connect(context.Background(), peerInfo); err != nil {
				log.Printf("Failed to connect to peer %s: %v", peerInfo.ID, err)
			}
		}(p)
	}
	wg.Wait()
	return nil
}

// SetupSecureConnection setups TLS/SSL security for the node.
func (n *NetworkNodes) SetupSecureConnection() error {
	config := &tls.Config{
		Certificates:       []tls.Certificate{ /* load your certificates */ },
		InsecureSkipVerify: true,
	}

	// Example of setting up a secure listener
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go handleSecureConnection(conn)
	}
}

// handleSecureConnection handles incoming secure connections.
func handleSecureConnection(conn net.Conn) {
	defer conn.Close()
	// Implement your handling logic here
	log.Printf("Secure connection established with %v", conn.RemoteAddr())
}

// main function to setup and start the network node
func main() {
	// Setup private key and pre-shared key for the node
	privKey, _, _ := crypto.GenerateKeyPair(crypto.RSA, 2048)
	psk := pnet.GenerateV1PSK()

	node, err := NewNetworkNode("/ip4/0.0.0.0/tcp/4001", privKey, psk)
	if err != nil {
		log.Fatalf("Failed to create network node: %v", err)
	}

	if err := node.SetupSecureConnection(); err != nil {
		log.Fatalf("Failed to setup secure connection: %v", err)
	}

	log.Println("Network node started successfully")
}
