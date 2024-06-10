package bridge_solutions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// BridgeMechanism defines the structure for cross-chain interactions
type BridgeMechanism struct {
	SecurityProtocol string
}

// NewBridgeMechanism initializes a new bridge mechanism with the specified security protocol
func NewBridgeMechanism(protocol string) *BridgeMechanism {
	return &BridgeMechanism{
		SecurityProtocol: protocol,
	}
}

// EncryptData uses the chosen encryption protocol to secure data before sending to another blockchain
func (bm *BridgeMechanism) EncryptData(data []byte) ([]byte, error) {
	switch bm.SecurityProtocol {
	case "AES":
		return bm.encryptAES(data)
	case "Scrypt":
		// Placeholder for Scrypt encryption
	case "Argon2":
		// Placeholder for Argon2 encryption
	default:
		return nil, errors.New("unsupported encryption protocol")
	}
	return nil, errors.New("invalid encryption protocol")
}

// encryptAES handles AES encryption
func (bm *BridgeMechanism) encryptAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(generateKey())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// generateKey generates a secure key for AES encryption
func generateKey() []byte {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		panic("failed to generate a secure key")
	}
	return key
}

// SerializeData prepares data for transmission by converting it to JSON
func SerializeData(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

// DeserializeData converts JSON data back into the specified structure
func DeserializeData(data []byte, target interface{}) error {
	return json.Unmarshal(data, target)
}
