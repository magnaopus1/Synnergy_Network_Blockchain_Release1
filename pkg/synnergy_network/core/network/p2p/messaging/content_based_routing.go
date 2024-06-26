package messaging

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-pubsub"
	"golang.org/x/crypto/scrypt"
)

// ContentBasedRouting handles the content-based routing logic
type ContentBasedRouting struct {
	host      host.Host
	pubsub    *pubsub.PubSub
	topics    map[string]*pubsub.Topic
	topicMux  sync.RWMutex
	passphrase string
	routingMap map[string]func([]byte) bool
}

// NewContentBasedRouting initializes the content-based routing system
func NewContentBasedRouting(listenPort int, passphrase string) (*ContentBasedRouting, error) {
	h, err := libp2p.New(libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)))
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %v", err)
	}

	ps, err := pubsub.NewGossipSub(context.Background(), h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}

	return &ContentBasedRouting{
		host:       h,
		pubsub:     ps,
		topics:     make(map[string]*pubsub.Topic),
		passphrase: passphrase,
		routingMap: make(map[string]func([]byte) bool),
	}, nil
}

// EncryptMessage encrypts a message using AES
func (cbr *ContentBasedRouting) EncryptMessage(plaintext []byte) (string, error) {
	key, err := scrypt.Key([]byte(cbr.passphrase), []byte("somesalt"), 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a message using AES
func (cbr *ContentBasedRouting) DecryptMessage(ciphertext string) ([]byte, error) {
	key, err := scrypt.Key([]byte(cbr.passphrase), []byte("somesalt"), 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// JoinTopic joins a pubsub topic
func (cbr *ContentBasedRouting) JoinTopic(topic string) error {
	cbr.topicMux.Lock()
	defer cbr.topicMux.Unlock()

	if _, ok := cbr.topics[topic]; ok {
		return nil
	}

	t, err := cbr.pubsub.Join(topic)
	if err != nil {
		return fmt.Errorf("failed to join topic %s: %v", topic, err)
	}

	cbr.topics[topic] = t
	return nil
}

// RegisterRoutingRule registers a content-based routing rule
func (cbr *ContentBasedRouting) RegisterRoutingRule(ruleName string, ruleFunc func([]byte) bool) {
	cbr.routingMap[ruleName] = ruleFunc
}

// SendMessage sends an encrypted message to a pubsub topic
func (cbr *ContentBasedRouting) SendMessage(topic string, message []byte) error {
	cbr.topicMux.RLock()
	t, ok := cbr.topics[topic]
	cbr.topicMux.RUnlock()
	if !ok {
		return fmt.Errorf("not subscribed to topic %s", topic)
	}

	encryptedMessage, err := cbr.EncryptMessage(message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	return t.Publish(context.Background(), []byte(encryptedMessage))
}

// RouteMessage routes a message based on its content
func (cbr *ContentBasedRouting) RouteMessage(message []byte) (string, error) {
	for ruleName, ruleFunc := range cbr.routingMap {
		if ruleFunc(message) {
			return ruleName, nil
		}
	}
	return "", fmt.Errorf("no routing rule matched")
}

// ReceiveMessages sets up a handler for receiving messages from a pubsub topic
func (cbr *ContentBasedRouting) ReceiveMessages(topic string, handler func(peer.ID, []byte)) error {
	cbr.topicMux.RLock()
	t, ok := cbr.topics[topic]
	cbr.topicMux.RUnlock()
	if !ok {
		return fmt.Errorf("not subscribed to topic %s", topic)
	}

	sub, err := t.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic %s: %v", topic, err)
	}

	go func() {
		for {
			msg, err := sub.Next(context.Background())
			if err != nil {
				log.Printf("failed to get next message in topic %s: %v", topic, err)
				continue
			}

			decryptedMessage, err := cbr.DecryptMessage(string(msg.Data))
			if err != nil {
				log.Printf("failed to decrypt message: %v", err)
				continue
			}

			handler(msg.ReceivedFrom, decryptedMessage)
		}
	}()

	return nil
}

// Main function to demonstrate usage
func main() {
	listenPort := 4001
	passphrase := "securepassphrase"

	cbr, err := NewContentBasedRouting(listenPort, passphrase)
	if err != nil {
		log.Fatalf("failed to create content-based routing: %v", err)
	}

	topic := "test-topic"

	err = cbr.JoinTopic(topic)
	if err != nil {
		log.Fatalf("failed to join topic %s: %v", topic, err)
	}

	// Register a routing rule example
	cbr.RegisterRoutingRule("rule1", func(message []byte) bool {
		return string(message) == "important"
	})

	cbr.ReceiveMessages(topic, func(peerID peer.ID, message []byte) {
		log.Printf("Received message from %s: %s", peerID.Pretty(), string(message))
		rule, err := cbr.RouteMessage(message)
		if err != nil {
			log.Printf("failed to route message: %v", err)
		} else {
			log.Printf("Message routed to rule: %s", rule)
		}
	})

	message := []byte("Hello, world!")
	err = cbr.SendMessage(topic, message)
	if err != nil {
		log.Printf("failed to send message: %v", err)
	}
}
