package dynamic_fee_adjustment

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
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// FeeAdjustmentStrategy represents a fee adjustment strategy
type FeeAdjustmentStrategy interface {
	AdjustFee(currentFee float64, marketConditions MarketConditions) float64
}

// MarketConditions represents the current market conditions
type MarketConditions struct {
	TransactionVolume float64
	NetworkCongestion float64
	AssetVolatility   float64
}

// SimpleFeeAdjustmentStrategy implements a basic fee adjustment strategy
type SimpleFeeAdjustmentStrategy struct{}

// AdjustFee adjusts the fee based on simple rules
func (s *SimpleFeeAdjustmentStrategy) AdjustFee(currentFee float64, marketConditions MarketConditions) float64 {
	adjustedFee := currentFee

	if marketConditions.NetworkCongestion > 0.8 {
		adjustedFee *= 1.2
	} else if marketConditions.NetworkCongestion < 0.2 {
		adjustedFee *= 0.8
	}

	if marketConditions.AssetVolatility > 0.5 {
		adjustedFee *= 1.1
	} else if marketConditions.AssetVolatility < 0.1 {
		adjustedFee *= 0.9
	}

	return math.Max(0.001, adjustedFee) // Ensure fee does not drop below a minimum value
}

// FeeManager manages the dynamic adjustment of fees
type FeeManager struct {
	mu        sync.Mutex
	fees      map[string]float64
	strategy  FeeAdjustmentStrategy
	secretKey string
}

// NewFeeManager initializes a new FeeManager
func NewFeeManager(secretKey string, strategy FeeAdjustmentStrategy) *FeeManager {
	return &FeeManager{
		fees:      make(map[string]float64),
		strategy:  strategy,
		secretKey: secretKey,
	}
}

// SetFee sets the fee for a specific transaction type
func (fm *FeeManager) SetFee(transactionType string, fee float64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.fees[transactionType] = fee
	log.Printf("Set fee: %f for transaction type: %s", fee, transactionType)
}

// AdjustFees adjusts fees based on market conditions
func (fm *FeeManager) AdjustFees(marketConditions MarketConditions) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	for transactionType, currentFee := range fm.fees {
		adjustedFee := fm.strategy.AdjustFee(currentFee, marketConditions)
		fm.fees[transactionType] = adjustedFee
		log.Printf("Adjusted fee: %f for transaction type: %s", adjustedFee, transactionType)
	}
}

// GetFee returns the fee for a specific transaction type
func (fm *FeeManager) GetFee(transactionType string) (float64, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fee, exists := fm.fees[transactionType]
	if !exists {
		return 0, errors.New("fee not found for transaction type")
	}

	return fee, nil
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
