package strategy_optimization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Strategy represents a trading strategy
type Strategy struct {
	Name      string
	Parameters map[string]float64
	Performance float64
}

// OptimizationResult represents the result of an optimization process
type OptimizationResult struct {
	BestStrategy Strategy
	Timestamp    time.Time
}

// StrategyOptimizer represents the strategy optimization system
type StrategyOptimizer struct {
	mu            sync.Mutex
	strategies    []Strategy
	results       []OptimizationResult
	secretKey     string
}

// NewStrategyOptimizer initializes a new StrategyOptimizer
func NewStrategyOptimizer(secretKey string) *StrategyOptimizer {
	return &StrategyOptimizer{
		strategies:    []Strategy{},
		results:       []OptimizationResult{},
		secretKey:     secretKey,
	}
}

// AddStrategy adds a new strategy to the optimizer
func (so *StrategyOptimizer) AddStrategy(name string, parameters map[string]float64) {
	so.mu.Lock()
	defer so.mu.Unlock()

	strategy := Strategy{
		Name:       name,
		Parameters: parameters,
	}
	so.strategies = append(so.strategies, strategy)
	log.Printf("Added strategy: %+v", strategy)
}

// Optimize optimizes the strategies based on their performance
func (so *StrategyOptimizer) Optimize() {
	so.mu.Lock()
	defer so.mu.Unlock()

	var bestStrategy Strategy
	var bestPerformance float64 = math.Inf(-1)

	for _, strategy := range so.strategies {
		performance := so.evaluateStrategy(strategy)
		strategy.Performance = performance
		if performance > bestPerformance {
			bestPerformance = performance
			bestStrategy = strategy
		}
	}

	result := OptimizationResult{
		BestStrategy: bestStrategy,
		Timestamp:    time.Now(),
	}
	so.results = append(so.results, result)
	log.Printf("Optimization result: %+v", result)
}

// evaluateStrategy evaluates the performance of a strategy
func (so *StrategyOptimizer) evaluateStrategy(strategy Strategy) float64 {
	// Dummy implementation, replace with actual evaluation logic
	return rand.Float64() * 100
}

// GetResults returns the optimization results
func (so *StrategyOptimizer) GetResults() []OptimizationResult {
	so.mu.Lock()
	defer so.mu.Unlock()
	return so.results
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (so *StrategyOptimizer) Encrypt(message string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(so.secretKey), salt, 1<<15, 8, 1, 32)
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
func (so *StrategyOptimizer) Decrypt(encryptedMessage string) (string, error) {
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

	key, err := scrypt.Key([]byte(so.secretKey), salt, 1<<15, 8, 1, 32)
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

// ValidateStrategies validates the strategies in the optimizer
func (so *StrategyOptimizer) ValidateStrategies() error {
	so.mu.Lock()
	defer so.mu.Unlock()

	for _, strategy := range so.strategies {
		if len(strategy.Parameters) == 0 {
			return errors.New("strategy parameters must not be empty")
		}
	}
	return nil
}
