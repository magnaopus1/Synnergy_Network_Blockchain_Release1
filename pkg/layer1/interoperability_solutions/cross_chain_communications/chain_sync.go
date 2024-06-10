package cross_chain_communications

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// ChainSync handles the synchronization tasks between different blockchain networks.
type ChainSync struct {
	SourceChainID      string
	DestinationChainID string
	SecurityProtocol   cipher.Block
}

// NewChainSync initializes a new ChainSync with necessary parameters.
func NewChainSync(source, destination string, key []byte) (*ChainSync, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	return &ChainSync{
		SourceChainID:      source,
		DestinationChainID: destination,
		SecurityProtocol:   block,
	}, nil
}

// SyncData transfers data from the source chain to the destination chain.
func (cs *ChainSync) SyncData(data interface{}) error {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "failed to serialize data")
	}

	encryptedData, err := cs.encryptData(serializedData)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt data")
	}

	// Simulate sending data to the destination chain
	log.Println("Data sent to destination chain:", cs.DestinationChainID)
	// Here you would integrate the network sending logic

	return nil
}

// encryptData encrypts data using AES encryption.
func (cs *ChainSync) encryptData(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(cs.SecurityProtocol)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

// ValidateData ensures the integrity and authenticity of the data received from another chain.
func (cs *ChainSync) ValidateData(data []byte) (bool, error) {
	// Simulate data validation logic here
	log.Println("Validating data from source chain:", cs.SourceChainID)

	// Implement the actual validation mechanism, possibly using digital signatures or hash checks
	return true, nil
}
