package liquidity_pool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Constants for encryption
const (
	ScryptN = 32768
	ScryptR = 8
	ScryptP = 1
	KeyLen  = 32
)

// LiquidityPool represents a liquidity pool with assets and liquidity
type LiquidityPool struct {
	ID           string
	Assets       map[string]float64
	TotalLiquidity float64
	CreatedAt    time.Time
}

// LiquidityPoolManager manages multiple liquidity pools
type LiquidityPoolManager struct {
	Pools map[string]*LiquidityPool
	Lock  sync.Mutex
}

// NewLiquidityPoolManager creates a new LiquidityPoolManager instance
func NewLiquidityPoolManager() *LiquidityPoolManager {
	return &LiquidityPoolManager{
		Pools: make(map[string]*LiquidityPool),
	}
}

// CreatePool creates a new liquidity pool
func (manager *LiquidityPoolManager) CreatePool(asset1, asset2 string, amount1, amount2 float64) (*LiquidityPool, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(fmt.Sprintf("%s-%s", asset1, asset2))
	if err != nil {
		return nil, err
	}

	pool := &LiquidityPool{
		ID:             id,
		Assets:         map[string]float64{asset1: amount1, asset2: amount2},
		TotalLiquidity: amount1 + amount2,
		CreatedAt:      time.Now(),
	}

	manager.Pools[id] = pool
	return pool, nil
}

// GetPool retrieves a liquidity pool by ID
func (manager *LiquidityPoolManager) GetPool(id string) (*LiquidityPool, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return nil, errors.New("liquidity pool not found")
	}
	return pool, nil
}

// AddLiquidity adds liquidity to an existing pool
func (manager *LiquidityPoolManager) AddLiquidity(id, asset string, amount float64) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return errors.New("liquidity pool not found")
	}

	pool.Assets[asset] += amount
	pool.TotalLiquidity += amount

	return nil
}

// RemoveLiquidity removes liquidity from an existing pool
func (manager *LiquidityPoolManager) RemoveLiquidity(id, asset string, amount float64) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return errors.New("liquidity pool not found")
	}

	if pool.Assets[asset] < amount {
		return errors.New("insufficient liquidity")
	}

	pool.Assets[asset] -= amount
	pool.TotalLiquidity -= amount

	return nil
}

// SwapAssets swaps assets in a liquidity pool
func (manager *LiquidityPoolManager) SwapAssets(id, fromAsset, toAsset string, amount float64) (float64, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return 0, errors.New("liquidity pool not found")
	}

	if pool.Assets[fromAsset] < amount {
		return 0, errors.New("insufficient liquidity for the swap")
	}

	// Swap logic with constant product formula (x * y = k)
	k := pool.Assets[fromAsset] * pool.Assets[toAsset]
	pool.Assets[fromAsset] += amount
	pool.Assets[toAsset] = k / pool.Assets[fromAsset]

	return pool.Assets[toAsset], nil
}

// generateUniqueID generates a unique ID based on input
func generateUniqueID(input string) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s", input, hex.EncodeToString(randBytes))))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Encryption and decryption functions
func encrypt(data, passphrase string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, KeyLen)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return fmt.Sprintf("%x:%x", salt, ciphertext), nil
}

func decrypt(encrypted, passphrase string) (string, error) {
	parts := split(encrypted, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted data format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, KeyLen)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

func split(s, sep string) []string {
	var parts []string
	for len(s) > 0 {
		pos := len(s)
		if i := len(s) - len(sep); i >= 0 {
			if s[i:] == sep {
				pos = i
			}
		}
		parts = append(parts, s[:pos])
		s = s[pos+len(sep):]
	}
	return parts
}
