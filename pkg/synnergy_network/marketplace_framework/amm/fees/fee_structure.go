package fee_structure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// FeeType represents different types of fees
type FeeType string

const (
	TransactionFee FeeType = "TransactionFee"
	WithdrawalFee  FeeType = "WithdrawalFee"
	DepositFee     FeeType = "DepositFee"
)

// Fee represents the structure of a fee
type Fee struct {
	Type     FeeType
	Rate     float64
	Currency string
	MinFee   float64
	MaxFee   float64
}

// FeeManager manages the fee structures
type FeeManager struct {
	mu        sync.Mutex
	fees      map[FeeType]Fee
	secretKey string
}

// NewFeeManager initializes a new FeeManager
func NewFeeManager(secretKey string) *FeeManager {
	return &FeeManager{
		fees:      make(map[FeeType]Fee),
		secretKey: secretKey,
	}
}

// SetFee sets the fee structure for a specific fee type
func (fm *FeeManager) SetFee(feeType FeeType, rate float64, currency string, minFee float64, maxFee float64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fee := Fee{
		Type:     feeType,
		Rate:     rate,
		Currency: currency,
		MinFee:   minFee,
		MaxFee:   maxFee,
	}

	fm.fees[feeType] = fee
	log.Printf("Set fee: %+v", fee)
}

// GetFee returns the fee structure for a specific fee type
func (fm *FeeManager) GetFee(feeType FeeType) (Fee, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fee, exists := fm.fees[feeType]
	if !exists {
		return Fee{}, errors.New("fee not found for the given type")
	}

	return fee, nil
}

// CalculateFee calculates the fee based on the provided amount and fee type
func (fm *FeeManager) CalculateFee(feeType FeeType, amount float64) (float64, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fee, exists := fm.fees[feeType]
	if !exists {
		return 0, errors.New("fee not found for the given type")
	}

	calculatedFee := amount * fee.Rate
	if calculatedFee < fee.MinFee {
		calculatedFee = fee.MinFee
	} else if calculatedFee > fee.MaxFee {
		calculatedFee = fee.MaxFee
	}

	return calculatedFee, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (fm *FeeManager) Encrypt(message, secretKey string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a message using AES encryption with Scrypt derived key
func (fm *FeeManager) Decrypt(encryptedMessage, secretKey string) (string, error) {
	parts := split(encryptedMessage, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted message format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func split(s string, sep string) []string {
	var parts []string
	var buf []rune
	for _, r := range s {
		if string(r) == sep {
			parts = append(parts, string(buf))
			buf = []rune{}
		} else {
			buf = append(buf, r)
		}
	}
	parts = append(parts, string(buf))
	return parts
}

// Hash generates a SHA-256 hash of the input string
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// generateID generates a unique identifier
func generateID() string {
	return hex.EncodeToString(randBytes(16))
}

// randBytes generates random bytes of the given length
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// SecurePassword hashes a password using Argon2
func SecurePassword(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// VerifyPassword verifies a password against a hash using Argon2
func VerifyPassword(password, salt, hash string) bool {
	return SecurePassword(password, salt) == hash
}
