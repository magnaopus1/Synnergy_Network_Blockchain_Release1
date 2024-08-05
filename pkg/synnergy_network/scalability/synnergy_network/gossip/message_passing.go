package gossip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Message represents a message in the gossip protocol.
type Message struct {
	ID        string
	Timestamp int64
	Data      []byte
}

// Node represents a node participating in the gossip network.
type Node struct {
	Address string
}

// GossipProtocol manages the message passing for the gossip protocol.
type GossipProtocol struct {
	nodes       []Node
	messages    map[string]Message
	mu          sync.RWMutex
	key         []byte
	listener    net.Listener
	shutdownCh  chan struct{}
	receiveCh   chan Message
	broadcastCh chan Message
}

// NewGossipProtocol initializes a new GossipProtocol with an optional passphrase for data encryption.
func NewGossipProtocol(passphrase string) (*GossipProtocol, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &GossipProtocol{
		nodes:       []Node{},
		messages:    make(map[string]Message),
		key:         key,
		shutdownCh:  make(chan struct{}),
		receiveCh:   make(chan Message),
		broadcastCh: make(chan Message),
	}, nil
}

// AddNode adds a new node to the gossip protocol.
func (gp *GossipProtocol) AddNode(address string) {
	gp.mu.Lock()
	defer gp.mu.Unlock()

	gp.nodes = append(gp.nodes, Node{Address: address})
}

// RemoveNode removes a node from the gossip protocol.
func (gp *GossipProtocol) RemoveNode(address string) {
	gp.mu.Lock()
	defer gp.mu.Unlock()

	for i, node := range gp.nodes {
		if node.Address == address {
			gp.nodes = append(gp.nodes[:i], gp.nodes[i+1:]...)
			break
		}
	}
}

// Start initializes the gossip protocol, starting the message receiver and broadcaster.
func (gp *GossipProtocol) Start(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	gp.listener = listener

	go gp.receiveMessages()
	go gp.broadcastMessages()

	return nil
}

// Stop stops the gossip protocol, shutting down the message receiver and broadcaster.
func (gp *GossipProtocol) Stop() {
	close(gp.shutdownCh)
	gp.listener.Close()
}

// receiveMessages handles incoming messages from other nodes.
func (gp *GossipProtocol) receiveMessages() {
	for {
		conn, err := gp.listener.Accept()
		if err != nil {
			select {
			case <-gp.shutdownCh:
				return
			default:
				logError("accepting connection", err)
				continue
			}
		}

		go gp.handleConnection(conn)
	}
}

// handleConnection handles an individual connection from another node.
func (gp *GossipProtocol) handleConnection(conn net.Conn) {
	defer conn.Close()

	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, conn); err != nil {
		logError("reading from connection", err)
		return
	}

	encryptedData := buffer.Bytes()
	data, err := decrypt(encryptedData, gp.key)
	if err != nil {
		logError("decrypting data", err)
		return
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		logError("unmarshaling message", err)
		return
	}

	gp.mu.Lock()
	if _, exists := gp.messages[msg.ID]; !exists {
		gp.messages[msg.ID] = msg
		gp.receiveCh <- msg
	}
	gp.mu.Unlock()
}

// broadcastMessages handles broadcasting messages to other nodes.
func (gp *GossipProtocol) broadcastMessages() {
	for {
		select {
		case msg := <-gp.broadcastCh:
			gp.mu.RLock()
			for _, node := range gp.nodes {
				go gp.sendMessageToNode(node.Address, msg)
			}
			gp.mu.RUnlock()
		case <-gp.shutdownCh:
			return
		}
	}
}

// sendMessageToNode sends a message to a specific node.
func (gp *GossipProtocol) sendMessageToNode(address string, msg Message) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		logError("dialing node", err)
		return
	}
	defer conn.Close()

	data, err := json.Marshal(msg)
	if err != nil {
		logError("marshaling message", err)
		return
	}

	encryptedData, err := encrypt(data, gp.key)
	if err != nil {
		logError("encrypting data", err)
		return
	}

	if _, err := conn.Write(encryptedData); err != nil {
		logError("writing to connection", err)
		return
	}
}

// Broadcast sends a message to all nodes in the gossip protocol.
func (gp *GossipProtocol) Broadcast(data []byte) (string, error) {
	msgID := generateMessageID(data)
	msg := Message{
		ID:        msgID,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	gp.mu.Lock()
	if _, exists := gp.messages[msg.ID]; exists {
		gp.mu.Unlock()
		return msgID, nil
	}
	gp.messages[msg.ID] = msg
	gp.mu.Unlock()

	gp.broadcastCh <- msg

	return msgID, nil
}

// generateMessageID generates a unique ID for a message based on its data.
func generateMessageID(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// generateKey derives a key from the given passphrase using Argon2.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, nil
}

// encrypt encrypts the given data with the provided key using AES.
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

// decrypt decrypts the given data with the provided key using AES.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// saveToFile saves the data to a file.
func saveToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// loadFromFile loads the data from a file.
func loadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// Export exports the entire gossip protocol state to a JSON file.
func (gp *GossipProtocol) Export(filename string) error {
	gp.mu.RLock()
	defer gp.mu.RUnlock()

	data, err := json.Marshal(gp)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the gossip protocol state from a JSON file.
func (gp *GossipProtocol) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, gp)
	if err != nil {
		return err
	}

	return nil
}
