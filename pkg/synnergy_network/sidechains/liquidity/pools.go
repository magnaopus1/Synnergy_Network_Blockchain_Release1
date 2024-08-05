package liquidity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// Pool represents a liquidity pool with assets and balances
type Pool struct {
	mu       sync.RWMutex
	Assets   map[string]float64
	Balances map[string]float64
	Config   PoolConfig
}

// PoolConfig represents the configuration for a liquidity pool
type PoolConfig struct {
	FeeRate float64
}

// NewPool creates a new Pool instance
func NewPool(config PoolConfig) *Pool {
	return &Pool{
		Assets:   make(map[string]float64),
		Balances: make(map[string]float64),
		Config:   config,
	}
}

// AddAsset adds an asset to the pool with an initial balance
func (p *Pool) AddAsset(asset string, balance float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Assets[asset] = balance
	p.Balances[asset] = balance
}

// GetBalance retrieves the balance of a specific asset in the pool
func (p *Pool) GetBalance(asset string) (float64, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	balance, exists := p.Balances[asset]
	if !exists {
		return 0, fmt.Errorf("asset %s not found in pool", asset)
	}
	return balance, nil
}

// Swap performs an asset swap within the pool
func (p *Pool) Swap(inputAsset string, inputAmount float64, outputAsset string) (float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	inputBalance, exists := p.Balances[inputAsset]
	if !exists {
		return 0, fmt.Errorf("input asset %s not found in pool", inputAsset)
	}

	outputBalance, exists := p.Balances[outputAsset]
	if !exists {
		return 0, fmt.Errorf("output asset %s not found in pool", outputAsset)
	}

	if inputAmount > inputBalance {
		return 0, fmt.Errorf("insufficient balance for asset %s", inputAsset)
	}

	// Calculate the swap output amount using a constant product formula
	outputAmount := (inputAmount * outputBalance) / (inputBalance + inputAmount)

	// Apply the fee
	fee := outputAmount * p.Config.FeeRate
	outputAmount -= fee

	// Update the balances
	p.Balances[inputAsset] += inputAmount
	p.Balances[outputAsset] -= outputAmount

	return outputAmount, nil
}

// RemoveAsset removes an asset from the pool
func (p *Pool) RemoveAsset(asset string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.Balances[asset]; !exists {
		return fmt.Errorf("asset %s not found in pool", asset)
	}

	delete(p.Assets, asset)
	delete(p.Balances, asset)
	return nil
}

// GetAssets returns the list of assets in the pool
func (p *Pool) GetAssets() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	assets := make([]string, 0, len(p.Assets))
	for asset := range p.Assets {
		assets = append(assets, asset)
	}
	return assets
}

// Encryption/Decryption utilities

// GenerateKey derives a key from the password using scrypt
func GenerateKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
}

// Encrypt encrypts plaintext using AES
func Encrypt(plaintext, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key, err := GenerateKey(password, salt)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// Decrypt decrypts ciphertext using AES
func Decrypt(ciphertext, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	ciphertext = string(data[16:])

	key, err := GenerateKey(password, salt)
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

	nonce, ciphertext := []byte(ciphertext[:nonceSize]), []byte(ciphertext[nonceSize:])
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Hashing utility for sensitive data
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}
