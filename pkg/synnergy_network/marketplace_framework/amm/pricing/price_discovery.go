package price_discovery

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

// PriceDiscoveryType represents the type of price discovery mechanism
type PriceDiscoveryType string

const (
	OrderBookBased PriceDiscoveryType = "OrderBookBased"
	AMMBased       PriceDiscoveryType = "AMMBased"
)

// PriceDiscoveryMechanism represents a price discovery mechanism
type PriceDiscoveryMechanism struct {
	ID          string
	Type        PriceDiscoveryType
	Parameters  map[string]interface{}
	LastUpdated time.Time
}

// Order represents an order in the order book
type Order struct {
	ID        string
	Type      string
	Price     *big.Float
	Amount    *big.Float
	Timestamp time.Time
}

// OrderBook represents an order book for price discovery
type OrderBook struct {
	BuyOrders  []Order
	SellOrders []Order
}

// PriceDiscoveryEngine represents the price discovery engine
type PriceDiscoveryEngine struct {
	mu                     sync.Mutex
	mechanisms             map[string]PriceDiscoveryMechanism
	orderBooks             map[string]OrderBook
	secretKey              string
	ammLiquidityPools      map[string]*big.Float // Placeholder for AMM-based liquidity pools
	orderBookUpdateChannel chan OrderBook        // Channel to receive order book updates
}

// NewPriceDiscoveryEngine initializes a new PriceDiscoveryEngine
func NewPriceDiscoveryEngine(secretKey string) *PriceDiscoveryEngine {
	return &PriceDiscoveryEngine{
		mechanisms:             make(map[string]PriceDiscoveryMechanism),
		orderBooks:             make(map[string]OrderBook),
		secretKey:              secretKey,
		ammLiquidityPools:      make(map[string]*big.Float),
		orderBookUpdateChannel: make(chan OrderBook),
	}
}

// AddMechanism adds a new price discovery mechanism to the engine
func (pde *PriceDiscoveryEngine) AddMechanism(mechanismType PriceDiscoveryType, parameters map[string]interface{}) (string, error) {
	pde.mu.Lock()
	defer pde.mu.Unlock()

	id := generateID()
	mechanism := PriceDiscoveryMechanism{
		ID:          id,
		Type:        mechanismType,
		Parameters:  parameters,
		LastUpdated: time.Now(),
	}

	pde.mechanisms[id] = mechanism
	log.Printf("Added price discovery mechanism: %+v", mechanism)
	return id, nil
}

// UpdateMechanism updates an existing price discovery mechanism
func (pde *PriceDiscoveryEngine) UpdateMechanism(mechanismID string, parameters map[string]interface{}) error {
	pde.mu.Lock()
	defer pde.mu.Unlock()

	mechanism, exists := pde.mechanisms[mechanismID]
	if !exists {
		return errors.New("price discovery mechanism not found")
	}

	mechanism.Parameters = parameters
	mechanism.LastUpdated = time.Now()
	pde.mechanisms[mechanismID] = mechanism
	log.Printf("Updated price discovery mechanism: %+v", mechanism)
	return nil
}

// RemoveMechanism removes an existing price discovery mechanism
func (pde *PriceDiscoveryEngine) RemoveMechanism(mechanismID string) error {
	pde.mu.Lock()
	defer pde.mu.Unlock()

	_, exists := pde.mechanisms[mechanismID]
	if !exists {
		return errors.New("price discovery mechanism not found")
	}

	delete(pde.mechanisms, mechanismID)
	log.Printf("Removed price discovery mechanism: %s", mechanismID)
	return nil
}

// DiscoverPrice discovers the price based on the selected mechanism
func (pde *PriceDiscoveryEngine) DiscoverPrice(mechanismID, token string, marketData map[string]interface{}) (*big.Float, error) {
	pde.mu.Lock()
	defer pde.mu.Unlock()

	mechanism, exists := pde.mechanisms[mechanismID]
	if !exists {
		return nil, errors.New("price discovery mechanism not found")
	}

	var price *big.Float
	switch mechanism.Type {
	case OrderBookBased:
		price = pde.discoverPriceOrderBookBased(token)
	case AMMBased:
		price = pde.discoverPriceAMMBased(token)
	default:
		return nil, errors.New("unknown price discovery mechanism type")
	}

	log.Printf("Discovered price for token %s: %f", token, price)
	return price, nil
}

func (pde *PriceDiscoveryEngine) discoverPriceOrderBookBased(token string) *big.Float {
	orderBook, exists := pde.orderBooks[token]
	if !exists {
		return big.NewFloat(0)
	}

	// Example price discovery logic based on order book
	if len(orderBook.BuyOrders) > 0 && len(orderBook.SellOrders) > 0 {
		bestBuy := orderBook.BuyOrders[0].Price
		bestSell := orderBook.SellOrders[0].Price
		midPrice := new(big.Float).Add(bestBuy, bestSell)
		return midPrice.Quo(midPrice, big.NewFloat(2))
	}
	return big.NewFloat(0)
}

func (pde *PriceDiscoveryEngine) discoverPriceAMMBased(token string) *big.Float {
	liquidity, exists := pde.ammLiquidityPools[token]
	if !exists {
		return big.NewFloat(0)
	}

	// Example AMM-based price discovery logic
	// Placeholder: simply returning the liquidity value for demonstration
	return liquidity
}

// UpdateOrderBook updates the order book for a specific token
func (pde *PriceDiscoveryEngine) UpdateOrderBook(token string, orderBook OrderBook) {
	pde.mu.Lock()
	defer pde.mu.Unlock()

	pde.orderBooks[token] = orderBook
	log.Printf("Updated order book for token %s", token)
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (pde *PriceDiscoveryEngine) Encrypt(message, secretKey string) (string, error) {
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
func (pde *PriceDiscoveryEngine) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
