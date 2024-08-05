package high_frequency_trading

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

	"golang.org/x/crypto/scrypt"
)

// Trade represents a single trade
type Trade struct {
	Exchange     string
	CurrencyPair CurrencyPair
	Price        float64
	Quantity     float64
	Timestamp    time.Time
}

// CurrencyPair represents a pair of currencies
type CurrencyPair struct {
	Base  string
	Quote string
}

// HFTSystem represents the high-frequency trading system
type HFTSystem struct {
	mu          sync.Mutex
	trades      []Trade
	exchangeData map[string]map[CurrencyPair]OrderBook
	threshold   float64
	secretKey   string
}

// OrderBook represents the order book for a specific currency pair on an exchange
type OrderBook struct {
	Asks []Order
	Bids []Order
}

// Order represents a single order in the order book
type Order struct {
	Price    float64
	Quantity float64
}

// NewHFTSystem initializes a new HFTSystem
func NewHFTSystem(threshold float64, secretKey string) *HFTSystem {
	return &HFTSystem{
		trades:      []Trade{},
		exchangeData: make(map[string]map[CurrencyPair]OrderBook),
		threshold:   threshold,
		secretKey:   secretKey,
	}
}

// AddOrderBook adds or updates the order book for a specific exchange and currency pair
func (hft *HFTSystem) AddOrderBook(exchange string, pair CurrencyPair, orderBook OrderBook) {
	hft.mu.Lock()
	defer hft.mu.Unlock()

	if _, exists := hft.exchangeData[exchange]; !exists {
		hft.exchangeData[exchange] = make(map[CurrencyPair]OrderBook)
	}
	hft.exchangeData[exchange][pair] = orderBook
	hft.detectTradingOpportunities(exchange, pair)
}

// detectTradingOpportunities detects trading opportunities based on the order books
func (hft *HFTSystem) detectTradingOpportunities(exchange string, pair CurrencyPair) {
	orderBook := hft.exchangeData[exchange][pair]

	for ex, data := range hft.exchangeData {
		if ex == exchange {
			continue
		}

		otherOrderBook, exists := data[pair]
		if !exists {
			continue
		}

		hft.evaluateOrders(exchange, ex, pair, orderBook, otherOrderBook)
	}
}

// evaluateOrders evaluates the order books to find trading opportunities
func (hft *HFTSystem) evaluateOrders(exchange1, exchange2 string, pair CurrencyPair, orderBook1, orderBook2 OrderBook) {
	if len(orderBook1.Asks) == 0 || len(orderBook2.Bids) == 0 {
		return
	}

	bestAsk1 := orderBook1.Asks[0]
	bestBid2 := orderBook2.Bids[0]

	if bestBid2.Price-bestAsk1.Price > hft.threshold {
		hft.executeTrade(exchange1, exchange2, pair, bestAsk1.Price, bestBid2.Price, bestAsk1.Quantity)
	}
}

// executeTrade executes a trade between two exchanges
func (hft *HFTSystem) executeTrade(buyExchange, sellExchange string, pair CurrencyPair, buyPrice, sellPrice, quantity float64) {
	trade := Trade{
		Exchange:     buyExchange + " -> " + sellExchange,
		CurrencyPair: pair,
		Price:        buyPrice,
		Quantity:     quantity,
		Timestamp:    time.Now(),
	}

	hft.trades = append(hft.trades, trade)
	log.Printf("Executed trade: %+v", trade)
}

// GetTrades returns a list of executed trades
func (hft *HFTSystem) GetTrades() []Trade {
	hft.mu.Lock()
	defer hft.mu.Unlock()
	return hft.trades
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (hft *HFTSystem) Encrypt(message string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(hft.secretKey), salt, 1<<15, 8, 1, 32)
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
func (hft *HFTSystem) Decrypt(encryptedMessage string) (string, error) {
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

	key, err := scrypt.Key([]byte(hft.secretKey), salt, 1<<15, 8, 1, 32)
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

// ValidateTrades validates the executed trades
func (hft *HFTSystem) ValidateTrades() error {
	hft.mu.Lock()
	defer hft.mu.Unlock()

	for _, trade := range hft.trades {
		if trade.Quantity <= 0 {
			return errors.New("trade quantity must be greater than zero")
		}
	}
	return nil
}
