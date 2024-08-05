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
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

// RedundantMessage represents a message exchanged with redundancy.
type RedundantMessage struct {
	ID        string
	Timestamp int64
	Data      []byte
}

// Node represents a node participating in the redundancy protocol.
type Node struct {
	Address string
}

// RedundancyProtocol manages message redundancy across nodes.
type RedundancyProtocol struct {
	nodes       []Node
	messages    map[string]RedundantMessage
	mu          sync.RWMutex
	key         []byte
	listener    net.Listener
	shutdownCh  chan struct{}
	receiveCh   chan RedundantMessage
	broadcastCh chan RedundantMessage
	redundantCh chan RedundantMessage
}

// NewRedundancyProtocol initializes a new RedundancyProtocol with an optional passphrase for data encryption.
func NewRedundancyProtocol(passphrase string) (*RedundancyProtocol, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &RedundancyProtocol{
		nodes:       []Node{},
		messages:    make(map[string]RedundantMessage),
		key:         key,
		shutdownCh:  make(chan struct{}),
		receiveCh:   make(chan RedundantMessage),
		broadcastCh: make(chan RedundantMessage),
		redundantCh: make(chan RedundantMessage),
	}, nil
}

// AddNode adds a new node to the redundancy protocol.
func (rp *RedundancyProtocol) AddNode(address string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.nodes = append(rp.nodes, Node{Address: address})
}

// RemoveNode removes a node from the redundancy protocol.
func (rp *RedundancyProtocol) RemoveNode(address string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	for i, node := range rp.nodes {
		if node.Address == address {
			rp.nodes = append(rp.nodes[:i], rp.nodes[i+1:]...)
			break
		}
	}
}

// Start initializes the redundancy protocol, starting the message receiver and broadcaster.
func (rp *RedundancyProtocol) Start(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	rp.listener = listener

	go rp.receiveMessages()
	go rp.broadcastMessages()
	go rp.redundantMessages()

	return nil
}

// Stop stops the redundancy protocol, shutting down the message receiver and broadcaster.
func (rp *RedundancyProtocol) Stop() {
	close(rp.shutdownCh)
	rp.listener.Close()
}

// receiveMessages handles incoming messages from other nodes.
func (rp *RedundancyProtocol) receiveMessages() {
	for {
		conn, err := rp.listener.Accept()
		if err != nil {
			select {
			case <-rp.shutdownCh:
				return
			default:
				logError("accepting connection", err)
				continue
			}
		}

		go rp.handleConnection(conn)
	}
}

// handleConnection handles an individual connection from another node.
func (rp *RedundancyProtocol) handleConnection(conn net.Conn) {
	defer conn.Close()

	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, conn); err != nil {
		logError("reading from connection", err)
		return
	}

	encryptedData := buffer.Bytes()
	data, err := decrypt(encryptedData, rp.key)
	if err != nil {
		logError("decrypting data", err)
		return
	}

	var msg RedundantMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		logError("unmarshaling message", err)
		return
	}

	rp.mu.Lock()
	if _, exists := rp.messages[msg.ID]; !exists {
		rp.messages[msg.ID] = msg
		rp.receiveCh <- msg
		rp.redundantCh <- msg
	}
	rp.mu.Unlock()
}

// broadcastMessages handles broadcasting messages to other nodes.
func (rp *RedundancyProtocol) broadcastMessages() {
	for {
		select {
		case msg := <-rp.broadcastCh:
			rp.mu.RLock()
			for _, node := range rp.nodes {
				go rp.sendMessageToNode(node.Address, msg)
			}
			rp.mu.RUnlock()
		case <-rp.shutdownCh:
			return
		}
	}
}

// redundantMessages handles broadcasting redundant messages to ensure delivery.
func (rp *RedundancyProtocol) redundantMessages() {
	for {
		select {
		case msg := <-rp.redundantCh:
			time.Sleep(5 * time.Second) // delay for redundancy
			rp.mu.RLock()
			for _, node := range rp.nodes {
				go rp.sendMessageToNode(node.Address, msg)
			}
			rp.mu.RUnlock()
		case <-rp.shutdownCh:
			return
		}
	}
}

// sendMessageToNode sends a message to a specific node.
func (rp *RedundancyProtocol) sendMessageToNode(address string, msg RedundantMessage) {
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

	encryptedData, err := encrypt(data, rp.key)
	if err != nil {
		logError("encrypting data", err)
		return
	}

	if _, err := conn.Write(encryptedData); err != nil {
		logError("writing to connection", err)
		return
	}
}

// Broadcast sends a message to all nodes in the redundancy protocol.
func (rp *RedundancyProtocol) Broadcast(data []byte) (string, error) {
	msgID := generateMessageID(data)
	msg := RedundantMessage{
		ID:        msgID,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	rp.mu.Lock()
	if _, exists := rp.messages[msg.ID]; exists {
		rp.mu.Unlock()
		return msgID, nil
	}
	rp.messages[msg.ID] = msg
	rp.mu.Unlock()

	rp.broadcastCh <- msg
	rp.redundantCh <- msg

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

// Export exports the entire redundancy protocol state to a JSON file.
func (rp *RedundancyProtocol) Export(filename string) error {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	data, err := json.Marshal(rp)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the redundancy protocol state from a JSON file.
func (rp *RedundancyProtocol) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, rp)
	if err != nil {
		return err
	}

	return nil
}
