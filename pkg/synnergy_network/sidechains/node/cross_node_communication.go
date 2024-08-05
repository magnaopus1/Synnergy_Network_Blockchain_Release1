// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including cross-node communication for consensus and data propagation.
package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// CrossNodeCommunication manages the communication between nodes in the blockchain network.
type CrossNodeCommunication struct {
	NodeID        string
	Peers         map[string]string // map of peer node IDs to their addresses
	mutex         sync.Mutex
	encryptionKey []byte
}

// Message represents a message sent between nodes.
type Message struct {
	From    string
	Type    string
	Payload interface{}
}

// NewCrossNodeCommunication creates a new CrossNodeCommunication instance.
func NewCrossNodeCommunication(nodeID string, peers map[string]string, encryptionKey string) (*CrossNodeCommunication, error) {
	key, err := deriveKey(encryptionKey)
	if err != nil {
		return nil, err
	}

	return &CrossNodeCommunication{
		NodeID:        nodeID,
		Peers:         peers,
		encryptionKey: key,
	}, nil
}

// deriveKey derives a key from the given passphrase using scrypt.
func deriveKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
}

// Encrypt encrypts data using AES-GCM.
func (cnc *CrossNodeCommunication) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(cnc.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM.
func (cnc *CrossNodeCommunication) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(cnc.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SendMessage sends a message to a peer node.
func (cnc *CrossNodeCommunication) SendMessage(peerID string, msg Message) error {
	cnc.mutex.Lock()
	defer cnc.mutex.Unlock()

	peerAddress, exists := cnc.Peers[peerID]
	if !exists {
		return errors.New("peer not found")
	}

	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	msgData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	encryptedMsg, err := cnc.Encrypt(msgData)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMsg)
	return err
}

// ReceiveMessage listens for incoming messages from other nodes.
func (cnc *CrossNodeCommunication) ReceiveMessage(address string, handleMsg func(Message)) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go cnc.handleConnection(conn, handleMsg)
	}
}

// handleConnection handles an incoming connection and processes the message.
func (cnc *CrossNodeCommunication) handleConnection(conn net.Conn, handleMsg func(Message)) {
	defer conn.Close()

	data := make([]byte, 4096)
	n, err := conn.Read(data)
	if err != nil {
		fmt.Println("Error reading data:", err)
		return
	}

	decryptedData, err := cnc.Decrypt(data[:n])
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	var msg Message
	if err := json.Unmarshal(decryptedData, &msg); err != nil {
		fmt.Println("Error unmarshaling message:", err)
		return
	}

	handleMsg(msg)
}

// BroadcastMessage broadcasts a message to all peer nodes.
func (cnc *CrossNodeCommunication) BroadcastMessage(msg Message) {
	for peerID := range cnc.Peers {
		go func(peerID string) {
			if err := cnc.SendMessage(peerID, msg); err != nil {
				fmt.Printf("Error sending message to peer %s: %v\n", peerID, err)
			}
		}(peerID)
	}
}

// AddPeer adds a new peer to the network.
func (cnc *CrossNodeCommunication) AddPeer(peerID, address string) {
	cnc.mutex.Lock()
	defer cnc.mutex.Unlock()
	cnc.Peers[peerID] = address
}

// RemovePeer removes a peer from the network.
func (cnc *CrossNodeCommunication) RemovePeer(peerID string) {
	cnc.mutex.Lock()
	defer cnc.mutex.Unlock()
	delete(cnc.Peers, peerID)
}

// GetPeers returns the list of peers in the network.
func (cnc *CrossNodeCommunication) GetPeers() map[string]string {
	cnc.mutex.Lock()
	defer cnc.mutex.Unlock()
	return cnc.Peers
}
