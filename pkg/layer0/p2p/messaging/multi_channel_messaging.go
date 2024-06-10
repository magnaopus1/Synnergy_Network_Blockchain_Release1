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

// MessageType defines the type of message
type MessageType int

const (
	// ConsensusMessage is a message related to consensus updates
	ConsensusMessage MessageType = iota
	// TransactionMessage is a message related to transactions
	TransactionMessage
	// GeneralMessage is a general message type
	GeneralMessage
)

// Message represents a message in the network
type Message struct {
	Type      MessageType
	Content   []byte
	Priority  int
	Timestamp time.Time
}

// MessagingNode represents a node capable of sending and receiving messages
type MessagingNode struct {
	id         string
	messages   chan Message
	neighbors  map[string]*MessagingNode
	mutex      sync.Mutex
	channels   map[string]chan Message
	priorities map[MessageType]int
}

// NewMessagingNode creates a new MessagingNode
func NewMessagingNode(id string) *MessagingNode {
	return &MessagingNode{
		id:         id,
		messages:   make(chan Message, 100),
		neighbors:  make(map[string]*MessagingNode),
		channels:   make(map[string]chan Message),
		priorities: make(map[MessageType]int),
	}
}

// AddNeighbor adds a neighboring node to the node's list of neighbors
func (node *MessagingNode) AddNeighbor(neighbor *MessagingNode) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	node.neighbors[neighbor.id] = neighbor
}

// SendMessage sends a message to all neighboring nodes
func (node *MessagingNode) SendMessage(message Message) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	for _, neighbor := range node.neighbors {
		neighbor.ReceiveMessage(message)
	}
}

// ReceiveMessage receives a message and adds it to the node's message queue
func (node *MessagingNode) ReceiveMessage(message Message) {
	node.messages <- message
}

// StartProcessing starts processing received messages
func (node *MessagingNode) StartProcessing() {
	go func() {
		for message := range node.messages {
			node.handleMessage(message)
		}
	}()
}

// handleMessage processes a received message based on its type and priority
func (node *MessagingNode) handleMessage(message Message) {
	switch message.Type {
	case ConsensusMessage:
		fmt.Printf("Node %s handling Consensus Message: %s\n", node.id, string(message.Content))
	case TransactionMessage:
		fmt.Printf("Node %s handling Transaction Message: %s\n", node.id, string(message.Content))
	case GeneralMessage:
		fmt.Printf("Node %s handling General Message: %s\n", node.id, string(message.Content))
	default:
		fmt.Printf("Node %s received unknown message type: %s\n", node.id, string(message.Content))
	}
}

// SetPriority sets the priority for a given message type
func (node *MessagingNode) SetPriority(msgType MessageType, priority int) {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	node.priorities[msgType] = priority
}

// MultiChannelMessaging implements multi-channel messaging protocols
func (node *MessagingNode) MultiChannelMessaging() {
	node.mutex.Lock()
	defer node.mutex.Unlock()
	for _, neighbor := range node.neighbors {
		channel := make(chan Message, 100)
		node.channels[neighbor.id] = channel
		go node.processChannelMessages(channel, neighbor)
	}
}

// processChannelMessages processes messages from a specific channel
func (node *MessagingNode) processChannelMessages(channel chan Message, neighbor *MessagingNode) {
	for message := range channel {
		neighbor.ReceiveMessage(message)
	}
}

// SendMessageOnChannel sends a message on a specific channel
func (node *MessagingNode) SendMessageOnChannel(neighborID string, message Message) error {
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
	nodeA := NewMessagingNode("A")
	nodeB := NewMessagingNode("B")
	nodeC := NewMessagingNode("C")

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

	// Create and send messages
	message := Message{
		Type:      GeneralMessage,
		Content:   []byte(encryptedMessage),
		Priority:  1,
		Timestamp: time.Now(),
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
