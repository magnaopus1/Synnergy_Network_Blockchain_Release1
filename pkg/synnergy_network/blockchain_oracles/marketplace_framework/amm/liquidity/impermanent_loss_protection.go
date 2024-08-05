package impermanent_loss_protection

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

// LiquidityPosition represents a liquidity provider's position in a pool
type LiquidityPosition struct {
	ID          string
	Provider    string
	TokenA      string
	TokenB      string
	AmountA     float64
	AmountB     float64
	InitialValue float64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ILProtectionManager manages impermanent loss protection for liquidity providers
type ILProtectionManager struct {
	mu        sync.Mutex
	positions map[string]LiquidityPosition
	secretKey string
}

// NewILProtectionManager initializes a new ILProtectionManager
func NewILProtectionManager(secretKey string) *ILProtectionManager {
	return &ILProtectionManager{
		positions: make(map[string]LiquidityPosition),
		secretKey: secretKey,
	}
}

// AddLiquidityPosition adds a new liquidity position
func (ilpm *ILProtectionManager) AddLiquidityPosition(provider, tokenA, tokenB string, amountA, amountB float64) (string, error) {
	ilpm.mu.Lock()
	defer ilpm.mu.Unlock()

	id := generateID()
	initialValue := amountA + amountB // Simplified initial value calculation
	position := LiquidityPosition{
		ID:          id,
		Provider:    provider,
		TokenA:      tokenA,
		TokenB:      tokenB,
		AmountA:     amountA,
		AmountB:     amountB,
		InitialValue: initialValue,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	ilpm.positions[id] = position
	log.Printf("Added liquidity position: %+v", position)
	return id, nil
}

// RemoveLiquidityPosition removes a liquidity position and calculates compensation for impermanent loss
func (ilpm *ILProtectionManager) RemoveLiquidityPosition(id string, currentPriceA, currentPriceB float64) (float64, error) {
	ilpm.mu.Lock()
	defer ilpm.mu.Unlock()

	position, exists := ilpm.positions[id]
	if !exists {
		return 0, errors.New("position not found")
	}

	currentValue := (position.AmountA * currentPriceA) + (position.AmountB * currentPriceB)
	impermanentLoss := ilpm.calculateImpermanentLoss(position.InitialValue, currentValue)
	compensation := impermanentLoss // Simplified compensation calculation

	delete(ilpm.positions, id)
	log.Printf("Removed liquidity position: %+v, Compensation: %f", position, compensation)
	return compensation, nil
}

// calculateImpermanentLoss calculates the impermanent loss based on initial and current value
func (ilpm *ILProtectionManager) calculateImpermanentLoss(initialValue, currentValue float64) float64 {
	if currentValue > initialValue {
		return 0
	}
	return initialValue - currentValue
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (ilpm *ILProtectionManager) Encrypt(message, secretKey string) (string, error) {
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
func (ilpm *ILProtectionManager) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
