package centralized_control_tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"
)

// Token represents a basic structure of a blockchain token under centralized control.
type Token struct {
	ID          string    `json:"id"`
	Symbol      string    `json:"symbol"`
	TotalSupply float64   `json:"total_supply"`
	Creator     string    `json:"creator"`
	CreatedAt   time.Time `json:"created_at"`
}

// TokenManager handles the lifecycle of tokens including creation, transfers, and retirement.
type TokenManager struct {
	tokens         map[string]Token
	encryptionKey  []byte
}

// NewTokenManager creates a new instance of TokenManager with the provided encryption key.
func NewTokenManager(key []byte) *TokenManager {
	return &TokenManager{
		tokens:        make(map[string]Token),
		encryptionKey: key,
	}
}

// CreateToken initializes and registers a new token in the system.
func (tm *TokenManager) CreateToken(symbol string, supply float64, creator string) (Token, error) {
	newToken := Token{
		ID:          generateTokenID(),
		Symbol:      symbol,
		TotalSupply: supply,
		Creator:     creator,
		CreatedAt:   time.Now(),
	}

	tm.tokens[newToken.ID] = newToken
	log.Printf("Token created with ID %s by %s", newToken.ID, creator)
	return newToken, nil
}

// AdjustTokenSupply modifies the supply of an existing token, this could be an inflation or deflation.
func (tm *TokenManager) AdjustTokenSupply(tokenID string, newSupply float64) error {
	token, exists := tm.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.TotalSupply = newSupply
	tm.tokens[tokenID] = token
	log.Printf("Token supply adjusted for %s, new supply: %f", tokenID, newSupply)
	return nil
}

// RetireToken permanently removes a token from the system.
func (tm *TokenManager) RetireToken(tokenID string) error {
	_, exists := tm.tokens[tokenID]
	if !exists {
		return errors.New("token not found for retirement")
	}

	delete(tm.tokens, tokenID)
	log.Printf("Token %s has been retired", tokenID)
	return nil
}

// EncryptTokenDetails encrypts token data for secure storage or external transmission.
func (tm *TokenManager) EncryptTokenDetails(tokenID string) ([]byte, error) {
	token, exists := tm.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found for encryption")
	}

	data, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encryptData(data, tm.encryptionKey)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// decryptData decrypts data using AES-256-CBC, assuming the key is appropriate for this operation.
func decryptData(encryptedData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	decryptedData := make([]byte, len(encryptedData))
	cfb.XORKeyStream(decryptedData, encryptedData)

	return decryptedData, nil
}

// Helper function to generate a unique token ID.
func generateTokenID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("Failed to generate token ID:", err)
	}
	return fmt.Sprintf("%x", b)
}

// encryptData handles the encryption of any data using AES-256-CBC.
func encryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}
