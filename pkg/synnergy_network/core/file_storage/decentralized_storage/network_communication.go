// Package decentralized_storage manages network communications within the decentralized storage system of the Synnergy Network blockchain.
// This file implements functionalities for secure and efficient network communication between nodes in the decentralized storage network.
package decentralized_storage

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"synthron_blockchain/pkg/encryption"
	"synthron_blockchain/pkg/storage"
)

// Node represents a participant in the decentralized storage network.
type Node struct {
	Address   string
	TLSConfig *tls.Config
}

// NetworkManager manages network communications for decentralized storage.
type NetworkManager struct {
	localNode     *Node
	peers         map[string]*Node
	storageSystem *storage.DistributedHashTable
}

// NewNetworkManager creates a network manager for handling communications in decentralized storage.
func NewNetworkManager(localAddress string, storageSystem *storage.DistributedHashTable) *NetworkManager {
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{}, // Load your certificates here
		InsecureSkipVerify: true,                // Set to false in production
	}

	return &NetworkManager{
		localNode: &Node{
			Address:   localAddress,
			TLSConfig: tlsConfig,
		},
		peers:         make(map[string]*Node),
		storageSystem: storageSystem,
	}
}

// RegisterPeer adds a peer to the network.
func (nm *NetworkManager) RegisterPeer(address string) {
	peer := &Node{
		Address:   address,
		TLSConfig: nm.localNode.TLSConfig,
	}
	nm.peers[address] = peer
	fmt.Printf("Peer %s registered successfully.\n", address)
}

// SendFileChunk sends a file chunk to a peer node.
func (nm *NetworkManager) SendFileChunk(peerAddress string, chunk []byte) error {
	peer, exists := nm.peers[peerAddress]
	if !exists {
		return fmt.Errorf("peer %s not registered", peerAddress)
	}

	conn, err := tls.Dial("tcp", peer.Address, peer.TLSConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to peer %s: %v", peerAddress, err)
	}
	defer conn.Close()

	encryptedChunk, err := encryption.EncryptData(chunk)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	_, err = conn.Write(encryptedChunk)
	if err != nil {
		return fmt.Errorf("failed to send data to peer %s: %v", peerAddress, err)
	}

	fmt.Printf("Data sent to peer %s successfully.\n", peerAddress)
	return nil
}

// ReceiveFileChunk handles incoming file chunks from peers.
func (nm *NetworkManager) ReceiveFileChunk(conn net.Conn) {
	defer conn.Close()
	data, err := ioutil.ReadAll(conn)
	if err != nil {
		fmt.Printf("Error reading data: %v\n", err)
		return
	}

	decryptedData, err := encryption.DecryptData(data)
	if err != nil {
		fmt.Printf("Error decrypting data: %v\n", err)
		return
	}

	fmt.Println("Received data successfully, processing...")
	// Process the data, typically involving storage and further replication.
	if err := nm.storageSystem.Store(decryptedData); err != nil {
		fmt.Printf("Error storing data: %v\n", err)
	}
}

// StartListener initializes a listener for incoming connections from other nodes.
func (nm *NetworkManager) StartListener() {
	listener, err := tls.Listen("tcp", nm.localNode.Address, nm.localNode.TLSConfig)
	if err != nil {
		fmt.Printf("Failed to start listener: %v\n", err)
		return
	}
	defer listener.Close()

	fmt.Println("Listening for incoming connections...")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection: %v\n", err)
			continue
		}

		go nm.ReceiveFileChunk(conn)
	}
}

// Example usage of NetworkManager
func main() {
	storageSystem := storage.NewDistributedHashTable() // Assuming an existing implementation
	networkManager := NewNetworkManager("localhost:8080", storageSystem)

	networkManager.RegisterPeer("peer1_address")
	networkManager.StartListener()
}
