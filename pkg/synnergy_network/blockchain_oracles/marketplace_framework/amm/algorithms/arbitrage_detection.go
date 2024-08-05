package arbitrage_detection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// CurrencyPair represents a pair of currencies
type CurrencyPair struct {
	Base  string
	Quote string
}

// ArbitrageOpportunity represents a detected arbitrage opportunity
type ArbitrageOpportunity struct {
	BuyExchange  string
	SellExchange string
	CurrencyPair CurrencyPair
	BuyPrice     float64
	SellPrice    float64
	Profit       float64
	Timestamp    time.Time
}

// ArbitrageDetector represents the arbitrage detection system
type ArbitrageDetector struct {
	mu            sync.Mutex
	exchangeData  map[string]map[CurrencyPair]float64
	opportunities []ArbitrageOpportunity
	threshold     float64
	secretKey     string
}

// NewArbitrageDetector initializes a new ArbitrageDetector
func NewArbitrageDetector(threshold float64, secretKey string) *ArbitrageDetector {
	return &ArbitrageDetector{
		exchangeData:  make(map[string]map[CurrencyPair]float64),
		opportunities: []ArbitrageOpportunity{},
		threshold:     threshold,
		secretKey:     secretKey,
	}
}

// AddExchangeData adds price data for an exchange
func (ad *ArbitrageDetector) AddExchangeData(exchange string, pair CurrencyPair, price float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if _, exists := ad.exchangeData[exchange]; !exists {
		ad.exchangeData[exchange] = make(map[CurrencyPair]float64)
	}
	ad.exchangeData[exchange][pair] = price
	ad.detectArbitrage(exchange, pair, price)
}

// detectArbitrage detects arbitrage opportunities based on the given price data
func (ad *ArbitrageDetector) detectArbitrage(exchange string, pair CurrencyPair, price float64) {
	for ex, prices := range ad.exchangeData {
		if ex == exchange {
			continue
		}

		if otherPrice, exists := prices[pair]; exists {
			var buyExchange, sellExchange string
			var buyPrice, sellPrice float64

			if price < otherPrice && otherPrice-price > ad.threshold {
				buyExchange, sellExchange = exchange, ex
				buyPrice, sellPrice = price, otherPrice
			} else if otherPrice < price && price-otherPrice > ad.threshold {
				buyExchange, sellExchange = ex, exchange
				buyPrice, sellPrice = otherPrice, price
			} else {
				continue
			}

			profit := sellPrice - buyPrice
			opportunity := ArbitrageOpportunity{
				BuyExchange:  buyExchange,
				SellExchange: sellExchange,
				CurrencyPair: pair,
				BuyPrice:     buyPrice,
				SellPrice:    sellPrice,
				Profit:       profit,
				Timestamp:    time.Now(),
			}
			ad.opportunities = append(ad.opportunities, opportunity)
		}
	}
}

// GetOpportunities returns a list of detected arbitrage opportunities
func (ad *ArbitrageDetector) GetOpportunities() []ArbitrageOpportunity {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	return ad.opportunities
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (ad *ArbitrageDetector) Encrypt(message string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(ad.secretKey), salt, 1<<15, 8, 1, 32)
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
func (ad *ArbitrageDetector) Decrypt(encryptedMessage string) (string, error) {
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

	key, err := scrypt.Key([]byte(ad.secretKey), salt, 1<<15, 8, 1, 32)
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

// ValidateOpportunities validates the detected arbitrage opportunities
func (ad *ArbitrageDetector) ValidateOpportunities() error {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	for _, opp := range ad.opportunities {
		if math.Abs(opp.Profit) < ad.threshold {
			return errors.New("opportunity profit is below the threshold")
		}
	}
	return nil
}
