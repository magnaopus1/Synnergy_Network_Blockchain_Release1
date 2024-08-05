package liquidity_pools

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

// LiquidityPool represents a liquidity pool
type LiquidityPool struct {
	ID           string
	TokenA       string
	TokenB       string
	ReserveA     float64
	ReserveB     float64
	Liquidity    float64
	Participants map[string]float64 // Address to Liquidity Share
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// PoolManager manages liquidity pools
type PoolManager struct {
	mu    sync.Mutex
	pools map[string]LiquidityPool
}

// NewPoolManager initializes a new PoolManager
func NewPoolManager() *PoolManager {
	return &PoolManager{
		pools: make(map[string]LiquidityPool),
	}
}

// CreatePool creates a new liquidity pool
func (pm *PoolManager) CreatePool(tokenA, tokenB string) (string, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	id := generateID()
	pool := LiquidityPool{
		ID:           id,
		TokenA:       tokenA,
		TokenB:       tokenB,
		ReserveA:     0,
		ReserveB:     0,
		Liquidity:    0,
		Participants: make(map[string]float64),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	pm.pools[id] = pool
	log.Printf("Created liquidity pool: %+v", pool)
	return id, nil
}

// AddLiquidity adds liquidity to the pool
func (pm *PoolManager) AddLiquidity(poolID, participant string, amountA, amountB float64) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	pool.ReserveA += amountA
	pool.ReserveB += amountB
	liquidity := calculateLiquidity(amountA, amountB, pool.ReserveA, pool.ReserveB)
	pool.Liquidity += liquidity
	pool.Participants[participant] += liquidity
	pool.UpdatedAt = time.Now()

	pm.pools[poolID] = pool
	log.Printf("Added liquidity: %f of %s and %f of %s to pool: %+v", amountA, pool.TokenA, amountB, pool.TokenB, pool)
	return nil
}

// RemoveLiquidity removes liquidity from the pool
func (pm *PoolManager) RemoveLiquidity(poolID, participant string, liquidity float64) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolID]
	if !exists {
		return errors.New("pool not found")
	}

	if pool.Participants[participant] < liquidity {
		return errors.New("insufficient liquidity")
	}

	share := liquidity / pool.Liquidity
	amountA := share * pool.ReserveA
	amountB := share * pool.ReserveB

	pool.ReserveA -= amountA
	pool.ReserveB -= amountB
	pool.Liquidity -= liquidity
	pool.Participants[participant] -= liquidity
	if pool.Participants[participant] == 0 {
		delete(pool.Participants, participant)
	}
	pool.UpdatedAt = time.Now()

	pm.pools[poolID] = pool
	log.Printf("Removed liquidity: %f of %s and %f of %s from pool: %+v", amountA, pool.TokenA, amountB, pool.TokenB, pool)
	return nil
}

// SwapTokens swaps tokens in the pool
func (pm *PoolManager) SwapTokens(poolID, fromToken, toToken string, amountIn float64) (float64, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolID]
	if !exists {
		return 0, errors.New("pool not found")
	}

	if fromToken != pool.TokenA && fromToken != pool.TokenB {
		return 0, errors.New("invalid fromToken")
	}

	if toToken != pool.TokenA && toToken != pool.TokenB {
		return 0, errors.New("invalid toToken")
	}

	if fromToken == toToken {
		return 0, errors.New("fromToken and toToken cannot be the same")
	}

	var amountOut float64
	if fromToken == pool.TokenA {
		amountOut = calculateSwapOutput(amountIn, pool.ReserveA, pool.ReserveB)
		pool.ReserveA += amountIn
		pool.ReserveB -= amountOut
	} else {
		amountOut = calculateSwapOutput(amountIn, pool.ReserveB, pool.ReserveA)
		pool.ReserveB += amountIn
		pool.ReserveA -= amountOut
	}
	pool.UpdatedAt = time.Now()

	pm.pools[poolID] = pool
	log.Printf("Swapped %f of %s for %f of %s in pool: %+v", amountIn, fromToken, amountOut, toToken, pool)
	return amountOut, nil
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

// calculateSwapOutput calculates the output amount for a given input amount in a swap
func calculateSwapOutput(amountIn, reserveIn, reserveOut float64) float64 {
	amountInWithFee := amountIn * 0.997 // Assuming 0.3% fee
	return (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee)
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

// generateID generates a unique identifier for a pool
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
