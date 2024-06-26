package novel_features

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
)

// QuantumKey represents a quantum-generated key
type QuantumKey struct {
	Key       []byte
	CreatedAt int64
	Used      bool
}

// QuantumKeyPool manages a pool of quantum-generated keys
type QuantumKeyPool struct {
	keys     []*QuantumKey
	capacity int
	mutex    sync.Mutex
}

// NewQuantumKeyPool creates a new QuantumKeyPool with the specified capacity
func NewQuantumKeyPool(capacity int) *QuantumKeyPool {
	return &QuantumKeyPool{
		keys:     make([]*QuantumKey, 0, capacity),
		capacity: capacity,
	}
}

// GenerateQuantumKey generates a new quantum key
func GenerateQuantumKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// AddKey adds a new key to the pool
func (qp *QuantumKeyPool) AddKey(key []byte) error {
	qp.mutex.Lock()
	defer qp.mutex.Unlock()

	if len(qp.keys) >= qp.capacity {
		return errors.New("key pool is at full capacity")
	}

	quantumKey := &QuantumKey{
		Key:       key,
		CreatedAt: time.Now().Unix(),
		Used:      false,
	}

	qp.keys = append(qp.keys, quantumKey)
	return nil
}

// GetKey retrieves an unused key from the pool
func (qp *QuantumKeyPool) GetKey() (*QuantumKey, error) {
	qp.mutex.Lock()
	defer qp.mutex.Unlock()

	for _, key := range qp.keys {
		if !key.Used {
			key.Used = true
			return key, nil
		}
	}
	return nil, errors.New("no available keys in the pool")
}

// QuantumSecureChannel represents a secure communication channel
type QuantumSecureChannel struct {
	key []byte
}

// NewQuantumSecureChannel initializes a new QuantumSecureChannel
func NewQuantumSecureChannel(key []byte) *QuantumSecureChannel {
	return &QuantumSecureChannel{
		key: key,
	}
}

// Encrypt encrypts the given plaintext using AES-GCM
func (qsc *QuantumSecureChannel) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(qsc.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES-GCM
func (qsc *QuantumSecureChannel) Decrypt(ciphertext string) (string, error) {
	block, err := aes.NewCipher(qsc.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// QuantumSecureMessaging manages quantum-secure messaging channels
type QuantumSecureMessaging struct {
	channels map[string]*QuantumSecureChannel
	mutex    sync.Mutex
}

// NewQuantumSecureMessaging initializes a new QuantumSecureMessaging
func NewQuantumSecureMessaging() *QuantumSecureMessaging {
	return &QuantumSecureMessaging{
		channels: make(map[string]*QuantumSecureChannel),
	}
}

// CreateChannel creates a new secure channel with a unique ID
func (qsm *QuantumSecureMessaging) CreateChannel(channelID string, key []byte) {
	qsm.mutex.Lock()
	defer qsm.mutex.Unlock()
	qsm.channels[channelID] = NewQuantumSecureChannel(key)
}

// SendMessage sends an encrypted message over the specified channel
func (qsm *QuantumSecureMessaging) SendMessage(channelID, message string) (string, error) {
	qsm.mutex.Lock()
	channel, exists := qsm.channels[channelID]
	qsm.mutex.Unlock()

	if !exists {
		return "", errors.New("channel does not exist")
	}

	return channel.Encrypt(message)
}

// ReceiveMessage receives and decrypts a message over the specified channel
func (qsm *QuantumSecureMessaging) ReceiveMessage(channelID, encryptedMessage string) (string, error) {
	qsm.mutex.Lock()
	channel, exists := qsm.channels[channelID]
	qsm.mutex.Unlock()

	if !exists {
		return "", errors.New("channel does not exist")
	}

	return channel.Decrypt(encryptedMessage)
}

// main function for testing the implementation
func main() {
	keyPool := NewQuantumKeyPool(10)

	for i := 0; i < 5; i++ {
		key, _ := GenerateQuantumKey()
		keyPool.AddKey(key)
	}

	// Create a secure messaging instance
	secureMessaging := NewQuantumSecureMessaging()

	// Get a key from the pool
	key, err := keyPool.GetKey()
	if err != nil {
		panic(err)
	}

	// Create a secure channel
	channelID := "channel-1"
	secureMessaging.CreateChannel(channelID, key.Key)

	// Send a message
	encryptedMessage, err := secureMessaging.SendMessage(channelID, "Hello, Quantum World!")
	if err != nil {
		panic(err)
	}

	println("Encrypted Message:", encryptedMessage)

	// Receive the message
	decryptedMessage, err := secureMessaging.ReceiveMessage(channelID, encryptedMessage)
	if err != nil {
		panic(err)
	}

	println("Decrypted Message:", decryptedMessage)
}
