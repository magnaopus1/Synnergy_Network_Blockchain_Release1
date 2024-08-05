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

// SyncMessage represents a message exchanged during synchronization.
type SyncMessage struct {
	ID        string
	Timestamp int64
	Data      []byte
}

// Node represents a node participating in the synchronization protocol.
type Node struct {
	Address string
}

// SyncProtocol manages the synchronization of data across nodes.
type SyncProtocol struct {
	nodes       []Node
	messages    map[string]SyncMessage
	mu          sync.RWMutex
	key         []byte
	listener    net.Listener
	shutdownCh  chan struct{}
	receiveCh   chan SyncMessage
	broadcastCh chan SyncMessage
	syncCh      chan SyncMessage
}

// NewSyncProtocol initializes a new SyncProtocol with an optional passphrase for data encryption.
func NewSyncProtocol(passphrase string) (*SyncProtocol, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &SyncProtocol{
		nodes:       []Node{},
		messages:    make(map[string]SyncMessage),
		key:         key,
		shutdownCh:  make(chan struct{}),
		receiveCh:   make(chan SyncMessage),
		broadcastCh: make(chan SyncMessage),
		syncCh:      make(chan SyncMessage),
	}, nil
}

// AddNode adds a new node to the synchronization protocol.
func (sp *SyncProtocol) AddNode(address string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	sp.nodes = append(sp.nodes, Node{Address: address})
}

// RemoveNode removes a node from the synchronization protocol.
func (sp *SyncProtocol) RemoveNode(address string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	for i, node := range sp.nodes {
		if node.Address == address {
			sp.nodes = append(sp.nodes[:i], sp.nodes[i+1:]...)
			break
		}
	}
}

// Start initializes the synchronization protocol, starting the message receiver and broadcaster.
func (sp *SyncProtocol) Start(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	sp.listener = listener

	go sp.receiveMessages()
	go sp.broadcastMessages()
	go sp.syncMessages()

	return nil
}

// Stop stops the synchronization protocol, shutting down the message receiver and broadcaster.
func (sp *SyncProtocol) Stop() {
	close(sp.shutdownCh)
	sp.listener.Close()
}

// receiveMessages handles incoming messages from other nodes.
func (sp *SyncProtocol) receiveMessages() {
	for {
		conn, err := sp.listener.Accept()
		if err != nil {
			select {
			case <-sp.shutdownCh:
				return
			default:
				logError("accepting connection", err)
				continue
			}
		}

		go sp.handleConnection(conn)
	}
}

// handleConnection handles an individual connection from another node.
func (sp *SyncProtocol) handleConnection(conn net.Conn) {
	defer conn.Close()

	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, conn); err != nil {
		logError("reading from connection", err)
		return
	}

	encryptedData := buffer.Bytes()
	data, err := decrypt(encryptedData, sp.key)
	if err != nil {
		logError("decrypting data", err)
		return
	}

	var msg SyncMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		logError("unmarshaling message", err)
		return
	}

	sp.mu.Lock()
	if _, exists := sp.messages[msg.ID]; !exists {
		sp.messages[msg.ID] = msg
		sp.receiveCh <- msg
		sp.syncCh <- msg
	}
	sp.mu.Unlock()
}

// broadcastMessages handles broadcasting messages to other nodes.
func (sp *SyncProtocol) broadcastMessages() {
	for {
		select {
		case msg := <-sp.broadcastCh:
			sp.mu.RLock()
			for _, node := range sp.nodes {
				go sp.sendMessageToNode(node.Address, msg)
			}
			sp.mu.RUnlock()
		case <-sp.shutdownCh:
			return
		}
	}
}

// syncMessages handles broadcasting synchronization messages to ensure consistency.
func (sp *SyncProtocol) syncMessages() {
	for {
		select {
		case msg := <-sp.syncCh:
			time.Sleep(5 * time.Second) // delay for synchronization
			sp.mu.RLock()
			for _, node := range sp.nodes {
				go sp.sendMessageToNode(node.Address, msg)
			}
			sp.mu.RUnlock()
		case <-sp.shutdownCh:
			return
		}
	}
}

// sendMessageToNode sends a message to a specific node.
func (sp *SyncProtocol) sendMessageToNode(address string, msg SyncMessage) {
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

	encryptedData, err := encrypt(data, sp.key)
	if err != nil {
		logError("encrypting data", err)
		return
	}

	if _, err := conn.Write(encryptedData); err != nil {
		logError("writing to connection", err)
		return
	}
}

// Broadcast sends a message to all nodes in the synchronization protocol.
func (sp *SyncProtocol) Broadcast(data []byte) (string, error) {
	msgID := generateMessageID(data)
	msg := SyncMessage{
		ID:        msgID,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	sp.mu.Lock()
	if _, exists := sp.messages[msg.ID]; exists {
		sp.mu.Unlock()
		return msgID, nil
	}
	sp.messages[msg.ID] = msg
	sp.mu.Unlock()

	sp.broadcastCh <- msg
	sp.syncCh <- msg

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

// Export exports the entire synchronization protocol state to a JSON file.
func (sp *SyncProtocol) Export(filename string) error {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	data, err := json.Marshal(sp)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports the synchronization protocol state from a JSON file.
func (sp *SyncProtocol) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, sp)
	if err != nil {
		return err
	}

	return nil
}
