// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including data propagation mechanisms for efficient and secure distribution of blockchain data.
package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// DataPropagation handles the distribution of blockchain data among nodes.
type DataPropagation struct {
	NodeID        string
	Peers         map[string]string // map of peer node IDs to their addresses
	mutex         sync.Mutex
	encryptionKey []byte
}

// Block represents a basic block structure for the blockchain.
type Block struct {
	Index     int
	Timestamp string
	Data      string
	PrevHash  string
	Hash      string
}

// NewDataPropagation creates a new DataPropagation instance.
func NewDataPropagation(nodeID string, peers map[string]string, encryptionKey string) (*DataPropagation, error) {
	key, err := deriveKey(encryptionKey)
	if err != nil {
		return nil, err
	}

	return &DataPropagation{
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
func (dp *DataPropagation) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dp.encryptionKey)
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
func (dp *DataPropagation) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(dp.encryptionKey)
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

// SendBlock sends a block to a peer node.
func (dp *DataPropagation) SendBlock(peerID string, block Block) error {
	dp.mutex.Lock()
	defer dp.mutex.Unlock()

	peerAddress, exists := dp.Peers[peerID]
	if !exists {
		return errors.New("peer not found")
	}

	conn, err := net.Dial("tcp", peerAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	blockData, err := encodeBlock(block)
	if err != nil {
		return err
	}

	encryptedBlock, err := dp.Encrypt(blockData)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedBlock)
	return err
}

// ReceiveBlock listens for incoming blocks from other nodes.
func (dp *DataPropagation) ReceiveBlock(address string, handleBlock func(Block)) error {
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

		go dp.handleConnection(conn, handleBlock)
	}
}

// handleConnection handles an incoming connection and processes the block.
func (dp *DataPropagation) handleConnection(conn net.Conn, handleBlock func(Block)) {
	defer conn.Close()

	data := make([]byte, 4096)
	n, err := conn.Read(data)
	if err != nil {
		fmt.Println("Error reading data:", err)
		return
	}

	decryptedData, err := dp.Decrypt(data[:n])
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	block, err := decodeBlock(decryptedData)
	if err != nil {
		fmt.Println("Error decoding block:", err)
		return
	}

	handleBlock(block)
}

// BroadcastBlock broadcasts a block to all peer nodes.
func (dp *DataPropagation) BroadcastBlock(block Block) {
	for peerID := range dp.Peers {
		go func(peerID string) {
			if err := dp.SendBlock(peerID, block); err != nil {
				fmt.Printf("Error sending block to peer %s: %v\n", peerID, err)
			}
		}(peerID)
	}
}

// AddPeer adds a new peer to the network.
func (dp *DataPropagation) AddPeer(peerID, address string) {
	dp.mutex.Lock()
	defer dp.mutex.Unlock()
	dp.Peers[peerID] = address
}

// RemovePeer removes a peer from the network.
func (dp *DataPropagation) RemovePeer(peerID string) {
	dp.mutex.Lock()
	defer dp.mutex.Unlock()
	delete(dp.Peers, peerID)
}

// GetPeers returns the list of peers in the network.
func (dp *DataPropagation) GetPeers() map[string]string {
	dp.mutex.Lock()
	defer dp.mutex.Unlock()
	return dp.Peers
}

// encodeBlock encodes a Block into bytes using gob encoding.
func encodeBlock(block Block) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(block)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeBlock decodes bytes into a Block using gob encoding.
func decodeBlock(data []byte) (Block, error) {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	var block Block
	err := dec.Decode(&block)
	if err != nil {
		return Block{}, err
	}
	return block, nil
}
