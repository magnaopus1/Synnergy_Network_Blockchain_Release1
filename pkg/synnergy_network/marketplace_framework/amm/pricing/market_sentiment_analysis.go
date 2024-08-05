package market_sentiment_analysis

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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// SentimentType represents the type of market sentiment
type SentimentType string

const (
	Bullish  SentimentType = "Bullish"
	Bearish  SentimentType = "Bearish"
	Neutral  SentimentType = "Neutral"
)

// MarketSentiment represents the market sentiment data
type MarketSentiment struct {
	Timestamp  time.Time
	Sentiment  SentimentType
	Confidence *big.Float
}

// SentimentAnalysisEngine represents the market sentiment analysis engine
type SentimentAnalysisEngine struct {
	mu               sync.Mutex
	sentimentHistory map[string][]MarketSentiment
	secretKey        string
}

// NewSentimentAnalysisEngine initializes a new SentimentAnalysisEngine
func NewSentimentAnalysisEngine(secretKey string) *SentimentAnalysisEngine {
	return &SentimentAnalysisEngine{
		sentimentHistory: make(map[string][]MarketSentiment),
		secretKey:        secretKey,
	}
}

// AnalyzeMarketSentiment analyzes the market sentiment based on input data
func (sae *SentimentAnalysisEngine) AnalyzeMarketSentiment(token string, marketData map[string]interface{}) (SentimentType, error) {
	sae.mu.Lock()
	defer sae.mu.Unlock()

	sentiment, confidence := sae.calculateSentiment(marketData)
	marketSentiment := MarketSentiment{
		Timestamp:  time.Now(),
		Sentiment:  sentiment,
		Confidence: confidence,
	}
	sae.sentimentHistory[token] = append(sae.sentimentHistory[token], marketSentiment)

	log.Printf("Analyzed market sentiment for token %s: %+v", token, marketSentiment)
	return sentiment, nil
}

// calculateSentiment calculates the sentiment based on market data
func (sae *SentimentAnalysisEngine) calculateSentiment(marketData map[string]interface{}) (SentimentType, *big.Float) {
	// Example sentiment calculation logic
	priceChange := marketData["priceChange"].(float64)
	volumeChange := marketData["volumeChange"].(float64)

	if priceChange > 0 && volumeChange > 0 {
		return Bullish, big.NewFloat(0.8)
	} else if priceChange < 0 && volumeChange > 0 {
		return Bearish, big.NewFloat(0.7)
	}
	return Neutral, big.NewFloat(0.5)
}

// GetSentimentHistory returns the sentiment history for a specific token
func (sae *SentimentAnalysisEngine) GetSentimentHistory(token string) ([]MarketSentiment, error) {
	sae.mu.Lock()
	defer sae.mu.Unlock()

	history, exists := sae.sentimentHistory[token]
	if !exists {
		return nil, errors.New("sentiment history not found")
	}

	return history, nil
}

// Encrypt encrypts a message using AES encryption with Scrypt derived key
func (sae *SentimentAnalysisEngine) Encrypt(message, secretKey string) (string, error) {
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
func (sae *SentimentAnalysisEngine) Decrypt(encryptedMessage, secretKey string) (string, error) {
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
