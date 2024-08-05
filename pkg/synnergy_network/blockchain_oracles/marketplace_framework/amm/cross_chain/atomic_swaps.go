package atomic_swaps

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// SwapStatus represents the status of a swap
type SwapStatus string

const (
	Pending   SwapStatus = "Pending"
	Completed SwapStatus = "Completed"
	Failed    SwapStatus = "Failed"
)

// Swap represents an atomic swap
type Swap struct {
	ID               string
	Sender           string
	Receiver         string
	SenderCurrency   string
	ReceiverCurrency string
	Amount           float64
	Status           SwapStatus
	Timestamp        time.Time
	HashLock         string
	SecretKey        string
}

// SwapManager manages atomic swaps
type SwapManager struct {
	mu    sync.Mutex
	swaps map[string]Swap
}

// NewSwapManager initializes a new SwapManager
func NewSwapManager() *SwapManager {
	return &SwapManager{
		swaps: make(map[string]Swap),
	}
}

// InitiateSwap initiates a new atomic swap
func (sm *SwapManager) InitiateSwap(sender, receiver, senderCurrency, receiverCurrency string, amount float64, secretKey string) (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := generateID()
	hashLock := generateHashLock(secretKey)

	swap := Swap{
		ID:               id,
		Sender:           sender,
		Receiver:         receiver,
		SenderCurrency:   senderCurrency,
		ReceiverCurrency: receiverCurrency,
		Amount:           amount,
		Status:           Pending,
		Timestamp:        time.Now(),
		HashLock:         hashLock,
		SecretKey:        secretKey,
	}

	sm.swaps[id] = swap
	log.Printf("Initiated swap: %+v", swap)
	return id, nil
}

// CompleteSwap completes an atomic swap
func (sm *SwapManager) CompleteSwap(id, secretKey string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	swap, exists := sm.swaps[id]
	if !exists {
		return errors.New("swap not found")
	}

	if swap.Status != Pending {
		return errors.New("swap is not in a pending state")
	}

	if swap.HashLock != generateHashLock(secretKey) {
		return errors.New("invalid secret key")
	}

	swap.Status = Completed
	swap.Timestamp = time.Now()
	sm.swaps[id] = swap
	log.Printf("Completed swap: %+v", swap)
	return nil
}

// FailSwap marks a swap as failed
func (sm *SwapManager) FailSwap(id string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	swap, exists := sm.swaps[id]
	if !exists {
		return errors.New("swap not found")
	}

	swap.Status = Failed
	swap.Timestamp = time.Now()
	sm.swaps[id] = swap
	log.Printf("Failed swap: %+v", swap)
	return nil
}

// GetSwap returns the details of a swap
func (sm *SwapManager) GetSwap(id string) (Swap, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	swap, exists := sm.swaps[id]
	if !exists {
		return Swap{}, errors.New("swap not found")
	}

	return swap, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (sm *SwapManager) Encrypt(message, secretKey string) (string, error) {
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
func (sm *SwapManager) Decrypt(encryptedMessage, secretKey string) (string, error) {
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

// generateID generates a unique identifier for a swap
func generateID() string {
	return hex.EncodeToString(randBytes(16))
}

// generateHashLock generates a hash lock for a given secret key
func generateHashLock(secretKey string) string {
	return Hash(secretKey)
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
