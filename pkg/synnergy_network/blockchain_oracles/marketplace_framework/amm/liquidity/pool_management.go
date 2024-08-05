package pool_management

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

// LiquidityPool represents a liquidity pool
type LiquidityPool struct {
	ID            string
	TokenA        string
	TokenB        string
	ReserveA      float64
	ReserveB      float64
	TotalLiquidity float64
	Providers     map[string]LiquidityProvider
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// LiquidityProvider represents a liquidity provider in a pool
type LiquidityProvider struct {
	ProviderID string
	Share      float64
}

// PoolManager manages liquidity pools
type PoolManager struct {
	mu        sync.Mutex
	pools     map[string]LiquidityPool
	secretKey string
}

// NewPoolManager initializes a new PoolManager
func NewPoolManager(secretKey string) *PoolManager {
	return &PoolManager{
		pools:     make(map[string]LiquidityPool),
		secretKey: secretKey,
	}
}

// CreatePool creates a new liquidity pool
func (pm *PoolManager) CreatePool(tokenA, tokenB string) (string, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	id := generateID()
	pool := LiquidityPool{
		ID:            id,
		TokenA:        tokenA,
		TokenB:        tokenB,
		ReserveA:      0,
		ReserveB:      0,
		TotalLiquidity: 0,
		Providers:     make(map[string]LiquidityProvider),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	pm.pools[id] = pool
	log.Printf("Created liquidity pool: %+v", pool)
	return id, nil
}

// AddLiquidity adds liquidity to the pool
func (pm *PoolManager) AddLiquidity(poolID, providerID string, amountA, amountB float64) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	pool.ReserveA += amountA
	pool.ReserveB += amountB
	liquidity := calculateLiquidity(amountA, amountB, pool.ReserveA, pool.ReserveB)
	pool.TotalLiquidity += liquidity

	provider, exists := pool.Providers[providerID]
	if !exists {
		provider = LiquidityProvider{
			ProviderID: providerID,
			Share:      0,
		}
	}
	provider.Share += liquidity
	pool.Providers[providerID] = provider
	pool.UpdatedAt = time.Now()

	pm.pools[poolID] = pool
	log.Printf("Added liquidity: %f of %s and %f of %s to pool: %+v", amountA, pool.TokenA, amountB, pool.TokenB, pool)
	return nil
}

// RemoveLiquidity removes liquidity from the pool
func (pm *PoolManager) RemoveLiquidity(poolID, providerID string, liquidity float64) (float64, float64, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolID]
	if !exists {
		return 0, 0, errors.New("pool not found")
	}

	provider, exists := pool.Providers[providerID]
	if !exists || provider.Share < liquidity {
		return 0, 0, errors.New("insufficient liquidity")
	}

	share := liquidity / pool.TotalLiquidity
	amountA := share * pool.ReserveA
	amountB := share * pool.ReserveB

	pool.ReserveA -= amountA
	pool.ReserveB -= amountB
	pool.TotalLiquidity -= liquidity
	provider.Share -= liquidity

	if provider.Share == 0 {
		delete(pool.Providers, providerID)
	} else {
		pool.Providers[providerID] = provider
	}
	pool.UpdatedAt = time.Now()

	pm.pools[poolID] = pool
	log.Printf("Removed liquidity: %f of %s and %f of %s from pool: %+v", amountA, pool.TokenA, amountB, pool.TokenB, pool)
	return amountA, amountB, nil
}

// GetPool returns the details of a pool
func (pm *PoolManager) GetPool(poolID string) (LiquidityPool, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolID]
	if !exists {
		return LiquidityPool{}, errors.New("pool not found")
	}

	return pool, nil
}

// calculateLiquidity calculates the amount of liquidity added to the pool
func calculateLiquidity(amountA, amountB, reserveA, reserveB float64) float64 {
	if reserveA == 0 || reserveB == 0 {
		return math.Sqrt(amountA * amountB)
	}
	return math.Min(amountA*reserveB/reserveA, amountB*reserveA/reserveB)
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (pm *PoolManager) Encrypt(message, secretKey string) (string, error) {
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
func (pm *PoolManager) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
