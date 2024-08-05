package asset_transfer_mechanisms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Syn800Token represents an interoperability token on the blockchain
type Syn800Token struct {
	TokenID        string    // Unique identifier for the interoperability token
	OriginalChain  string    // The original blockchain of the token
	OriginalToken  string    // Identifier for the original token
	WrappedAmount  big.Int   // Amount of token wrapped
	Owner          string    // Address of the token owner
	WrappedAt      time.Time // Timestamp of when the token was wrapped
	Unwrapped      bool      // Whether the token has been unwrapped
}

// Syn800TokenManager manages Syn800Tokens
type Syn800TokenManager struct {
	syn800Tokens map[string]*Syn800Token
	mu           sync.Mutex
}

// NewSyn800TokenManager creates a new Syn800TokenManager
func NewSyn800TokenManager() *Syn800TokenManager {
	return &Syn800TokenManager{
		syn800Tokens: make(map[string]*Syn800Token),
	}
}

// WrapToken wraps a token from another blockchain into a Syn800Token
func (stm *Syn800TokenManager) WrapToken(originalChain, originalToken, owner string, amount big.Int) (string, error) {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	tokenID := generateTokenID(originalChain, originalToken, owner, amount)
	if _, exists := stm.syn800Tokens[tokenID]; exists {
		return "", errors.New("token already wrapped")
	}

	syn800Token := &Syn800Token{
		TokenID:       tokenID,
		OriginalChain: originalChain,
		OriginalToken: originalToken,
		WrappedAmount: amount,
		Owner:         owner,
		WrappedAt:     time.Now(),
		Unwrapped:     false,
	}

	stm.syn800Tokens[tokenID] = syn800Token

	return tokenID, nil
}

// UnwrapToken unwraps a Syn800Token
func (stm *Syn800TokenManager) UnwrapToken(tokenID, owner string) error {
	stm.mu.Lock()
	defer stm.mu.Unlock()

	syn800Token, exists := stm.syn800Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	if syn800Token.Owner != owner {
		return errors.New("unauthorized owner")
	}

	if syn800Token.Unwrapped {
		return errors.New("token already unwrapped")
	}

	// Perform the unwrapping process (mocked here)
	fmt.Printf("Unwrapping %s tokens of %s from %s to %s\n", syn800Token.WrappedAmount.String(), syn800Token.OriginalToken, syn800Token.OriginalChain, syn800Token.Owner)

	syn800Token.Unwrapped = true
	return nil
}

// generateTokenID generates a unique token ID
func generateTokenID(originalChain, originalToken, owner string, amount big.Int) string {
	data := originalChain + originalToken + owner + amount.String() + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// EncryptSecret encrypts a secret using AES
func EncryptSecret(secret, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, secret, nil)
	return ciphertext, nil
}

// DecryptSecret decrypts an AES encrypted secret
func DecryptSecret(ciphertext, key []byte) ([]byte, error) {
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateKey derives a key using scrypt
func GenerateKey(passphrase, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}
