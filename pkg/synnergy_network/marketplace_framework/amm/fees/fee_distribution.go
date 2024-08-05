package fee_distribution

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
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Distribution represents a fee distribution event
type Distribution struct {
	ID            string
	Amount        float64
	Recipients    map[string]float64 // address to share percentage
	Timestamp     time.Time
	Executed      bool
}

// FeeDistributor manages the distribution of fees
type FeeDistributor struct {
	mu           sync.Mutex
	distributions map[string]Distribution
	secretKey     string
}

// NewFeeDistributor initializes a new FeeDistributor
func NewFeeDistributor(secretKey string) *FeeDistributor {
	return &FeeDistributor{
		distributions: make(map[string]Distribution),
		secretKey:     secretKey,
	}
}

// CreateDistribution creates a new fee distribution
func (fd *FeeDistributor) CreateDistribution(amount float64, recipients map[string]float64) (string, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	id := generateID()
	distribution := Distribution{
		ID:         id,
		Amount:     amount,
		Recipients: recipients,
		Timestamp:  time.Now(),
		Executed:   false,
	}

	fd.distributions[id] = distribution
	log.Printf("Created distribution: %+v", distribution)
	return id, nil
}

// ExecuteDistribution executes the fee distribution
func (fd *FeeDistributor) ExecuteDistribution(id string) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	distribution, exists := fd.distributions[id]
	if !exists {
		return errors.New("distribution not found")
	}

	if distribution.Executed {
		return errors.New("distribution already executed")
	}

	for recipient, share := range distribution.Recipients {
		amount := distribution.Amount * share
		log.Printf("Distributed %f to %s", amount, recipient)
		// Add logic to transfer the amount to recipient address
	}

	distribution.Executed = true
	distribution.Timestamp = time.Now()
	fd.distributions[id] = distribution
	log.Printf("Executed distribution: %+v", distribution)
	return nil
}

// GetDistribution returns the details of a distribution
func (fd *FeeDistributor) GetDistribution(id string) (Distribution, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	distribution, exists := fd.distributions[id]
	if !exists {
		return Distribution{}, errors.New("distribution not found")
	}

	return distribution, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (fd *FeeDistributor) Encrypt(message, secretKey string) (string, error) {
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
func (fd *FeeDistributor) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
