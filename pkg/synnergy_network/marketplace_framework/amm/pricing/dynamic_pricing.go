package dynamic_pricing

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

// PriceStrategyType represents the type of a pricing strategy
type PriceStrategyType string

const (
	MarketBased PriceStrategyType = "MarketBased"
	TimeBased   PriceStrategyType = "TimeBased"
	DemandBased PriceStrategyType = "DemandBased"
)

// PricingStrategy represents a dynamic pricing strategy
type PricingStrategy struct {
	ID          string
	Type        PriceStrategyType
	Parameters  map[string]interface{}
	LastUpdated time.Time
}

// Price represents a price with its timestamp
type Price struct {
	Value     *big.Float
	Timestamp time.Time
}

// PricingEngine represents the dynamic pricing engine
type PricingEngine struct {
	mu              sync.Mutex
	pricingStrategies map[string]PricingStrategy
	priceHistory    map[string][]Price
	secretKey       string
}

// NewPricingEngine initializes a new PricingEngine
func NewPricingEngine(secretKey string) *PricingEngine {
	return &PricingEngine{
		pricingStrategies: make(map[string]PricingStrategy),
		priceHistory:    make(map[string][]Price),
		secretKey:       secretKey,
	}
}

// AddPricingStrategy adds a new pricing strategy to the engine
func (pe *PricingEngine) AddPricingStrategy(strategyType PriceStrategyType, parameters map[string]interface{}) (string, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	id := generateID()
	strategy := PricingStrategy{
		ID:          id,
		Type:        strategyType,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}

	pe.pricingStrategies[id] = strategy
	log.Printf("Added pricing strategy: %+v", strategy)
	return id, nil
}

// UpdatePricingStrategy updates an existing pricing strategy
func (pe *PricingEngine) UpdatePricingStrategy(strategyID string, parameters map[string]interface{}) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	strategy, exists := pe.pricingStrategies[strategyID]
	if !exists {
		return errors.New("pricing strategy not found")
	}

	strategy.Parameters = parameters
	strategy.LastUpdated = time.Now()
	pe.pricingStrategies[strategyID] = strategy
	log.Printf("Updated pricing strategy: %+v", strategy)
	return nil
}

// RemovePricingStrategy removes an existing pricing strategy
func (pe *PricingEngine) RemovePricingStrategy(strategyID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	_, exists := pe.pricingStrategies[strategyID]
	if !exists {
		return errors.New("pricing strategy not found")
	}

	delete(pe.pricingStrategies, strategyID)
	log.Printf("Removed pricing strategy: %s", strategyID)
	return nil
}

// CalculatePrice calculates the price based on the strategy and current market conditions
func (pe *PricingEngine) CalculatePrice(strategyID, token string, marketData map[string]interface{}) (*big.Float, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	strategy, exists := pe.pricingStrategies[strategyID]
	if !exists {
		return nil, errors.New("pricing strategy not found")
	}

	var price *big.Float
	switch strategy.Type {
	case MarketBased:
		price = pe.calculateMarketBasedPrice(marketData)
	case TimeBased:
		price = pe.calculateTimeBasedPrice(strategy.Parameters)
	case DemandBased:
		price = pe.calculateDemandBasedPrice(strategy.Parameters, marketData)
	default:
		return nil, errors.New("unknown pricing strategy type")
	}

	pe.updatePriceHistory(token, price)
	log.Printf("Calculated price for token %s: %f", token, price)
	return price, nil
}

func (pe *PricingEngine) calculateMarketBasedPrice(marketData map[string]interface{}) *big.Float {
	// Implement market-based pricing logic here
	// Example: Use the average price from market data
	averagePrice := big.NewFloat(0)
	count := 0
	for _, value := range marketData {
		price := value.(*big.Float)
		averagePrice.Add(averagePrice, price)
		count++
	}
	if count > 0 {
		averagePrice.Quo(averagePrice, big.NewFloat(float64(count)))
	}
	return averagePrice
}

func (pe *PricingEngine) calculateTimeBasedPrice(parameters map[string]interface{}) *big.Float {
	// Implement time-based pricing logic here
	// Example: Use a base price and adjust based on time of day
	basePrice := parameters["basePrice"].(*big.Float)
	timeFactor := big.NewFloat(time.Now().Hour())
	return basePrice.Mul(basePrice, timeFactor)
}

func (pe *PricingEngine) calculateDemandBasedPrice(parameters map[string]interface{}, marketData map[string]interface{}) *big.Float {
	// Implement demand-based pricing logic here
	// Example: Adjust price based on supply and demand
	basePrice := parameters["basePrice"].(*big.Float)
	demandFactor := big.NewFloat(float64(len(marketData))) // Example demand factor based on market data length
	return basePrice.Mul(basePrice, demandFactor)
}

func (pe *PricingEngine) updatePriceHistory(token string, price *big.Float) {
	priceEntry := Price{
		Value:     price,
		Timestamp: time.Now(),
	}
	pe.priceHistory[token] = append(pe.priceHistory[token], priceEntry)
}

// GetPriceHistory returns the price history for a specific token
func (pe *PricingEngine) GetPriceHistory(token string) ([]Price, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	history, exists := pe.priceHistory[token]
	if !exists {
		return nil, errors.New("price history not found")
	}

	return history, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (pe *PricingEngine) Encrypt(message, secretKey string) (string, error) {
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
func (pe *PricingEngine) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
