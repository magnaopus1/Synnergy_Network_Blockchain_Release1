package self_destructing_nodes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Node represents a blockchain node
type Node struct {
	ID              string
	Data            []byte
	EncryptionKey   []byte
	TamperDetected  bool
	LastCheckedTime time.Time
}

// GenerateKey generates a secure encryption key using scrypt
func GenerateKey(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptData encrypts the given data with the provided key
func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the given data with the provided key
func DecryptData(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// HashData creates a SHA-256 hash of the given data
func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CheckForTampering checks if the node's data has been tampered with
func (n *Node) CheckForTampering() bool {
	expectedHash := HashData(n.Data)
	currentHash := HashData(n.EncryptionKey)

	n.LastCheckedTime = time.Now()
	n.TamperDetected = expectedHash != currentHash
	return n.TamperDetected
}

// SelfDestruct securely deletes the node's data if tampering is detected
func (n *Node) SelfDestruct() error {
	if n.TamperDetected {
		n.Data = nil
		n.EncryptionKey = nil
		return nil
	}
	return errors.New("tampering not detected; self-destruct aborted")
}

// NewNode initializes a new node with encrypted data
func NewNode(id string, data []byte, password string) (*Node, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := GenerateKey([]byte(password), salt)
	if err != nil {
		return nil, err
	}

	encryptedData, err := EncryptData(data, key)
	if err != nil {
		return nil, err
	}

	return &Node{
		ID:            id,
		Data:          encryptedData,
		EncryptionKey: key,
	}, nil
}

// PeriodicCheck periodically checks nodes for tampering
func PeriodicCheck(nodes []*Node, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, node := range nodes {
				if node.CheckForTampering() {
					fmt.Printf("Tampering detected in node %s at %s\n", node.ID, node.LastCheckedTime)
					node.SelfDestruct()
				}
			}
		}
	}
}
