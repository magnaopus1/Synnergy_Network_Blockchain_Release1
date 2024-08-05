package slippage_protection

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

// OrderType represents the type of an order
type OrderType string

const (
	Buy  OrderType = "Buy"
	Sell OrderType = "Sell"
)

// Order represents a trade order
type Order struct {
	ID        string
	Type      OrderType
	Token     string
	Price     *big.Float
	Amount    *big.Float
	Timestamp time.Time
	MinPrice  *big.Float
	MaxPrice  *big.Float
}

// OrderBook represents an order book for a specific token
type OrderBook struct {
	Token      string
	BuyOrders  []Order
	SellOrders []Order
}

// SlippageProtectionEngine represents the slippage protection engine
type SlippageProtectionEngine struct {
	mu         sync.Mutex
	orderBooks map[string]OrderBook
	secretKey  string
}

// NewSlippageProtectionEngine initializes a new SlippageProtectionEngine
func NewSlippageProtectionEngine(secretKey string) *SlippageProtectionEngine {
	return &SlippageProtectionEngine{
		orderBooks: make(map[string]OrderBook),
		secretKey:  secretKey,
	}
}

// PlaceOrder places a new order in the slippage protection engine
func (spe *SlippageProtectionEngine) PlaceOrder(orderType OrderType, token string, price, amount, minPrice, maxPrice *big.Float) (string, error) {
	spe.mu.Lock()
	defer spe.mu.Unlock()

	id := generateID()
	order := Order{
		ID:        id,
		Type:      orderType,
		Token:     token,
		Price:     price,
		Amount:    amount,
		MinPrice:  minPrice,
		MaxPrice:  maxPrice,
		Timestamp: time.Now(),
	}

	orderBook, exists := spe.orderBooks[token]
	if !exists {
		orderBook = OrderBook{
			Token:      token,
			BuyOrders:  []Order{},
			SellOrders: []Order{},
		}
	}

	if orderType == Buy {
		orderBook.BuyOrders = append(orderBook.BuyOrders, order)
	} else {
		orderBook.SellOrders = append(orderBook.SellOrders, order)
	}

	spe.orderBooks[token] = orderBook
	log.Printf("Placed order: %+v", order)
	return id, nil
}

// CancelOrder cancels an existing order in the slippage protection engine
func (spe *SlippageProtectionEngine) CancelOrder(token, orderID string) error {
	spe.mu.Lock()
	defer spe.mu.Unlock()

	orderBook, exists := spe.orderBooks[token]
	if !exists {
		return errors.New("order book not found")
	}

	orderBook.BuyOrders, orderBook.SellOrders = spe.removeOrder(orderBook.BuyOrders, orderID), spe.removeOrder(orderBook.SellOrders, orderID)
	spe.orderBooks[token] = orderBook
	log.Printf("Cancelled order: %s", orderID)
	return nil
}

// removeOrder removes an order from the list by ID
func (spe *SlippageProtectionEngine) removeOrder(orders []Order, orderID string) []Order {
	for i, order := range orders {
		if order.ID == orderID {
			return append(orders[:i], orders[i+1:]...)
		}
	}
	return orders
}

// MatchOrders matches buy and sell orders in the slippage protection engine
func (spe *SlippageProtectionEngine) MatchOrders(token string) {
	spe.mu.Lock()
	defer spe.mu.Unlock()

	orderBook, exists := spe.orderBooks[token]
	if !exists {
		log.Printf("Order book not found for token: %s", token)
		return
	}

	var matchedOrders []Order
	for _, buyOrder := range orderBook.BuyOrders {
		for _, sellOrder := range orderBook.SellOrders {
			if buyOrder.Price.Cmp(sellOrder.Price) >= 0 && buyOrder.Price.Cmp(buyOrder.MinPrice) >= 0 && sellOrder.Price.Cmp(sellOrder.MaxPrice) <= 0 {
				matchedOrders = append(matchedOrders, buyOrder, sellOrder)

				amountToTrade := minAmount(buyOrder.Amount, sellOrder.Amount)
				buyOrder.Amount = big.NewFloat(0).Sub(buyOrder.Amount, amountToTrade)
				sellOrder.Amount = big.NewFloat(0).Sub(sellOrder.Amount, amountToTrade)

				if buyOrder.Amount.Cmp(big.NewFloat(0)) == 0 {
					orderBook.BuyOrders = spe.removeOrder(orderBook.BuyOrders, buyOrder.ID)
				}
				if sellOrder.Amount.Cmp(big.NewFloat(0)) == 0 {
					orderBook.SellOrders = spe.removeOrder(orderBook.SellOrders, sellOrder.ID)
				}
			}
		}
	}

	spe.orderBooks[token] = orderBook
	log.Printf("Matched orders: %+v", matchedOrders)
}

// minAmount returns the minimum amount between two big.Float values
func minAmount(a, b *big.Float) *big.Float {
	if a.Cmp(b) < 0 {
		return a
	}
	return b
}

// GetOrderBook returns the order book for a specific token
func (spe *SlippageProtectionEngine) GetOrderBook(token string) (OrderBook, error) {
	spe.mu.Lock()
	defer spe.mu.Unlock()

	orderBook, exists := spe.orderBooks[token]
	if !exists {
		return OrderBook{}, errors.New("order book not found")
	}

	return orderBook, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (spe *SlippageProtectionEngine) Encrypt(message, secretKey string) (string, error) {
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
func (spe *SlippageProtectionEngine) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
