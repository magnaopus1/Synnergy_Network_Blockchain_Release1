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

// AsynchronousMessaging handles the asynchronous messaging logic
type AsynchronousMessaging struct {
	host      host.Host
	pubsub    *pubsub.PubSub
	topics    map[string]*pubsub.Topic
	topicMux  sync.RWMutex
	passphrase string
}

// NewAsynchronousMessaging initializes the asynchronous messaging system
func NewAsynchronousMessaging(listenPort int, passphrase string) (*AsynchronousMessaging, error) {
	h, err := libp2p.New(libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)))
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %v", err)
	}

	ps, err := pubsub.NewGossipSub(context.Background(), h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}

	return &AsynchronousMessaging{
		host:       h,
		pubsub:     ps,
		topics:     make(map[string]*pubsub.Topic),
		passphrase: passphrase,
	}, nil
}

// EncryptMessage encrypts a message using AES
func (am *AsynchronousMessaging) EncryptMessage(plaintext []byte) (string, error) {
	key, err := scrypt.Key([]byte(am.passphrase), []byte("somesalt"), 32768, 8, 1, 32)
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
func (am *AsynchronousMessaging) DecryptMessage(ciphertext string) ([]byte, error) {
	key, err := scrypt.Key([]byte(am.passphrase), []byte("somesalt"), 32768, 8, 1, 32)
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
func (am *AsynchronousMessaging) JoinTopic(topic string) error {
	am.topicMux.Lock()
	defer am.topicMux.Unlock()

	if _, ok := am.topics[topic]; ok {
		return nil
	}

	t, err := am.pubsub.Join(topic)
	if err != nil {
		return fmt.Errorf("failed to join topic %s: %v", topic, err)
	}

	am.topics[topic] = t
	return nil
}

// SendMessage sends an encrypted message to a pubsub topic
func (am *AsynchronousMessaging) SendMessage(topic string, message []byte) error {
	am.topicMux.RLock()
	t, ok := am.topics[topic]
	am.topicMux.RUnlock()
	if !ok {
		return fmt.Errorf("not subscribed to topic %s", topic)
	}

	encryptedMessage, err := am.EncryptMessage(message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	return t.Publish(context.Background(), []byte(encryptedMessage))
}

// ReceiveMessages sets up a handler for receiving messages from a pubsub topic
func (am *AsynchronousMessaging) ReceiveMessages(topic string, handler func(peer.ID, []byte)) error {
	am.topicMux.RLock()
	t, ok := am.topics[topic]
	am.topicMux.RUnlock()
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

			decryptedMessage, err := am.DecryptMessage(string(msg.Data))
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

	am, err := NewAsynchronousMessaging(listenPort, passphrase)
	if err != nil {
		log.Fatalf("failed to create asynchronous messaging: %v", err)
	}

	topic := "test-topic"

	err = am.JoinTopic(topic)
	if err != nil {
		log.Fatalf("failed to join topic %s: %v", topic, err)
	}

	am.ReceiveMessages(topic, func(peerID peer.ID, message []byte) {
		log.Printf("Received message from %s: %s", peerID.Pretty(), string(message))
	})

	message := []byte("Hello, world!")
	err = am.SendMessage(topic, message)
	if err != nil {
		log.Printf("failed to send message: %v", err)
	}
}
