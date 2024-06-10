package proof_of_burn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"time"

	"github.com/synthron_blockchain/crypto"
)

// BurnRecord represents a record of a token burn operation.
type BurnRecord struct {
	TokenID   string    `json:"token_id"`
	Amount    float64   `json:"amount"`
	Timestamp time.Time `json:"timestamp"`
	BurnerID  string    `json:"burner_id"`
	Signature string    `json:"signature"`
}

// Burner interface defines methods for burning tokens.
type Burner interface {
	BurnTokens(record BurnRecord) error
	VerifyBurn(record BurnRecord) bool
}

// SimpleBurner implements the Burner interface using basic cryptographic operations.
type SimpleBurner struct {
	PrivateKey string
	PublicKey  string
}

// NewSimpleBurner creates a new SimpleBurner with given keys.
func NewSimpleBurner(privateKey, publicKey string) *SimpleBurner {
	return &SimpleBurner{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// BurnTokens permanently removes a specified amount of tokens from circulation.
func (sb *SimpleBurner) BurnTokens(record BurnRecord) error {
	if record.Amount <= 0 {
		return errors.New("invalid amount: amount must be positive")
	}

	// Simulate the burn by creating a transaction record
	log.Printf("Burning %f tokens for TokenID: %s by BurnerID: %s\n", record.Amount, record.TokenID, record.BurnerID)
	// Actual implementation would involve blockchain interactions to remove tokens

	// Sign the record to ensure it's not tampered with
	signature, err := crypto.Sign(sb.PrivateKey, []byte(record.String()))
	if err != nil {
		return err
	}
	record.Signature = hex.EncodeToString(signature)

	return nil
}

// VerifyBurn checks the validity of the burn record.
func (sb *SimpleBurner) VerifyBurn(record BurnRecord) bool {
	signatureBytes, _ := hex.DecodeString(record.Signature)
	isValid := crypto.Verify(sb.PublicKey, []byte(record.String()), signatureBytes)
	return isValid
}

// Utility method to convert BurnRecord to a string for signing.
func (record *BurnRecord) String() string {
	return record.TokenID + string(record.Amount) + record.BurnerID + record.Timestamp.String()
}

