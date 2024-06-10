package centralized_control_tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
)

// TokenSpec defines the specifications for a new token.
type TokenSpec struct {
	TokenID         string    `json:"token_id"`
	TokenType       string    `json:"token_type"`
	InitialSupply   float64   `json:"initial_supply"`
	CreationDate    time.Time `json:"creation_date"`
	Administrator   string    `json:"administrator"` // Responsible party for token management
}

// TokenCreator is responsible for creating and initializing new tokens.
type TokenCreator struct {
	encryptionKey []byte
}

// NewTokenCreator returns a new instance of TokenCreator with the specified encryption key.
func NewTokenCreator(key []byte) *TokenCreator {
	return &TokenCreator{
		encryptionKey: key,
	}
}

// CreateToken initializes a new token according to the provided TokenSpec.
func (tc *TokenCreator) CreateToken(spec TokenSpec) ([]byte, error) {
	spec.CreationDate = time.Now()

	// Serialize the token specification
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize token specification")
	}

	// Encrypt the serialized data
	encryptedData, err := tc.encryptData(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt token data")
	}

	log.Printf("Token created successfully: %s", spec.TokenID)
	return encryptedData, nil
}

// encryptData encrypts data using AES-256-GCM.
func (tc *TokenCreator) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(tc.encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// DecryptTokenData decrypts token data for administrative purposes.
func (tc *TokenCreator) DecryptTokenData(encryptedData []byte) (TokenSpec, error) {
	block, err := aes.NewCipher(tc.encryptionKey)
	if err != nil {
		return TokenSpec{}, errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return TokenSpec{}, errors.Wrap(err, "failed to create GCM")
	}

	if len(encryptedData) < gcm.NonceSize() {
		return TokenSpec{}, errors.New("invalid data size")
	}

	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return TokenSpec{}, errors.Wrap(err, "failed to decrypt data")
	}

	var spec TokenSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return TokenSpec{}, errors.Wrap(err, "failed to unmarshal token spec")
	}

	return spec, nil
}
