package messaging

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Metadata represents additional contextual information about a message
type Metadata struct {
	Timestamp  time.Time
	SenderID   string
	ReceiverID string
	OtherData  map[string]string
}

// SecureMessage represents a message with its metadata
type SecureMessage struct {
	Type      MessageType
	Content   []byte
	Priority  int
	Timestamp time.Time
	Metadata  Metadata
}

// SecureMetadataExchangeNode represents a node capable of sending and receiving secure messages with metadata
type SecureMetadataExchangeNode struct {
	id         string
	messages   chan SecureMessage
	neighbors  map[string]*SecureMetadataExchangeNode
	mutex      sync.Mutex
	channels   map[string]chan SecureMessage
	priorities map[MessageType]int
}

// NewSecureMetadataExchangeNode creates a new SecureMetadataExchangeNode
func NewSecureMetadataExchangeNode(id string) *SecureMetadataExchangeNode {
	return &SecureMetadataExchangeNode{
		id:         id,
		messages:   make(chan SecureMessage, 100),
		neighbors:  make(map[string]*SecureMetadataExchangeNode),
		channels:   make(map[string]chan SecureMessage),
		priorities: make(map[MessageType]int),
	}
}

// AddNeighbor adds a neighboring node to the node's list of neighbors
func (node *SecureMetadataExchangeNode) AddNeighbor(neighbor *SecureMetadataExchangeNode) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	node.neighbors[neighbor.id] = neighbor
}

// SendMessage sends a secure message to all neighboring nodes
func (node *SecureMetadataExchangeNode) SendMessage(message SecureMessage) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	for _, neighbor := range node.neighbors {
		neighbor.ReceiveMessage(message)
	}
}

// ReceiveMessage receives a secure message and adds it to the node's message queue
func (node *SecureMetadataExchangeNode) ReceiveMessage(message SecureMessage) {
	node.messages <- message
}

// StartProcessing starts processing received secure messages
func (node *SecureMetadataExchangeNode) StartProcessing() {
	go func() {
		for message := range node.messages {
			node.handleMessage(message)
		}
	}()
}

// handleMessage processes a received secure message based on its type and priority
func (node *SecureMetadataExchangeNode) handleMessage(message SecureMessage) {
	switch message.Type {
	case ConsensusMessage:
		fmt.Printf("Node %s handling Consensus Message: %s with Metadata: %+v\n", node.id, string(message.Content), message.Metadata)
	case TransactionMessage:
		fmt.Printf("Node %s handling Transaction Message: %s with Metadata: %+v\n", node.id, string(message.Content), message.Metadata)
	case GeneralMessage:
		fmt.Printf("Node %s handling General Message: %s with Metadata: %+v\n", node.id, string(message.Content), message.Metadata)
	default:
		fmt.Printf("Node %s received unknown message type: %s with Metadata: %+v\n", node.id, string(message.Content), message.Metadata)
	}
}

// SetPriority sets the priority for a given message type
func (node *SecureMetadataExchangeNode) SetPriority(msgType MessageType, priority int) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	node.priorities[msgType] = priority
}

// MultiChannelMessaging implements multi-channel messaging protocols
func (node *SecureMetadataExchangeNode) MultiChannelMessaging() {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	for _, neighbor := range node.neighbors {
		channel := make(chan SecureMessage, 100)
		node.channels[neighbor.id] = channel
		go node.processChannelMessages(channel, neighbor)
	}
}

// processChannelMessages processes secure messages from a specific channel
func (node *SecureMetadataExchangeNode) processChannelMessages(channel chan SecureMessage, neighbor *SecureMetadataExchangeNode) {
	for message := range channel {
		neighbor.ReceiveMessage(message)
	}
}

// SendMessageOnChannel sends a secure message on a specific channel
func (node *SecureMetadataExchangeNode) SendMessageOnChannel(neighborID string, message SecureMessage) error {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	channel, exists := node.channels[neighborID]
	if !exists {
		return errors.New("channel does not exist")
	}
	channel <- message
	return nil
}

// EncryptMessage encrypts a message using AES encryption
func EncryptMessage(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a message using AES encryption
func DecryptMessage(key []byte, ciphertext string) ([]byte, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Example usage
func main() {
	// Create nodes
	nodeA := NewSecureMetadataExchangeNode("A")
	nodeB := NewSecureMetadataExchangeNode("B")
	nodeC := NewSecureMetadataExchangeNode("C")

	// Add neighbors
	nodeA.AddNeighbor(nodeB)
	nodeA.AddNeighbor(nodeC)
	nodeB.AddNeighbor(nodeA)
	nodeC.AddNeighbor(nodeA)

	// Set message priorities
	nodeA.SetPriority(ConsensusMessage, 1)
	nodeA.SetPriority(TransactionMessage, 2)
	nodeA.SetPriority(GeneralMessage, 3)

	// Enable multi-channel messaging
	nodeA.MultiChannelMessaging()
	nodeB.MultiChannelMessaging()
	nodeC.MultiChannelMessaging()

	// Start processing messages
	nodeA.StartProcessing()
	nodeB.StartProcessing()
	nodeC.StartProcessing()

	// Encrypt a message
	key := sha256.Sum256([]byte("mysecretkey"))
	encryptedMessage, err := EncryptMessage(key[:], []byte("Hello, this is a test message"))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	// Create and send messages with metadata
	metadata := Metadata{
		Timestamp:  time.Now(),
		SenderID:   nodeA.id,
		ReceiverID: nodeB.id,
		OtherData: map[string]string{
			"Info": "Test message",
		},
	}
	message := SecureMessage{
		Type:      GeneralMessage,
		Content:   []byte(encryptedMessage),
		Priority:  1,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	nodeA.SendMessageOnChannel("B", message)

	// Decrypt the message
	decryptedMessage, err := DecryptMessage(key[:], encryptedMessage)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}
	fmt.Println("Decrypted message:", string(decryptedMessage))

	// Simulate some wait time
	time.Sleep(2 * time.Second)
}
