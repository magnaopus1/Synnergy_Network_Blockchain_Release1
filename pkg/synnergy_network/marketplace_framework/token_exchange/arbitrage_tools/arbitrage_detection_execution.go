package arbitrage_tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

type Trade struct {
	Exchange string  `json:"exchange"`
	Pair     string  `json:"pair"`
	Price    float64 `json:"price"`
	Amount   float64 `json:"amount"`
}

type ArbitrageOpportunity struct {
	BuyTrade  Trade  `json:"buy_trade"`
	SellTrade Trade  `json:"sell_trade"`
	Profit    float64 `json:"profit"`
	Timestamp time.Time `json:"timestamp"`
}

type ArbitrageDetector struct {
	sync.Mutex
	trades         map[string][]Trade
	arbitrageCh    chan ArbitrageOpportunity
	executionCh    chan ArbitrageOpportunity
	encryptionKey  string
}

func NewArbitrageDetector(encryptionKey string) *ArbitrageDetector {
	return &ArbitrageDetector{
		trades:         make(map[string][]Trade),
		arbitrageCh:    make(chan ArbitrageOpportunity, 100),
		executionCh:    make(chan ArbitrageOpportunity, 100),
		encryptionKey:  encryptionKey,
	}
}

func (ad *ArbitrageDetector) AddTrade(trade Trade) error {
	ad.Lock()
	defer ad.Unlock()

	encryptedTrade, err := ad.encryptTrade(trade)
	if err != nil {
		return err
	}

	ad.trades[trade.Pair] = append(ad.trades[trade.Pair], encryptedTrade)
	return nil
}

func (ad *ArbitrageDetector) DetectArbitrage(pair string) {
	ad.Lock()
	defer ad.Unlock()

	trades, exists := ad.trades[pair]
	if !exists {
		return
	}

	for i := 0; i < len(trades); i++ {
		for j := i + 1; j < len(trades); j++ {
			buyTrade, err := ad.decryptTrade(trades[i])
			if err != nil {
				continue
			}
			sellTrade, err := ad.decryptTrade(trades[j])
			if err != nil {
				continue
			}

			if buyTrade.Price < sellTrade.Price {
				profit := (sellTrade.Price - buyTrade.Price) * buyTrade.Amount
				opportunity := ArbitrageOpportunity{
					BuyTrade:  buyTrade,
					SellTrade: sellTrade,
					Profit:    profit,
					Timestamp: time.Now(),
				}
				ad.arbitrageCh <- opportunity
			}
		}
	}
}

func (ad *ArbitrageDetector) ExecuteArbitrage() {
	for opportunity := range ad.arbitrageCh {
		ad.executionCh <- opportunity
		log.Printf("Arbitrage executed: Buy on %s at %.2f, Sell on %s at %.2f, Profit: %.2f",
			opportunity.BuyTrade.Exchange, opportunity.BuyTrade.Price,
			opportunity.SellTrade.Exchange, opportunity.SellTrade.Price,
			opportunity.Profit)
	}
}

func (ad *ArbitrageDetector) encryptTrade(trade Trade) (Trade, error) {
	data, err := json.Marshal(trade)
	if err != nil {
		return Trade{}, err
	}

	encryptedData, err := encrypt(data, ad.encryptionKey)
	if err != nil {
		return Trade{}, err
	}

	var encryptedTrade Trade
	err = json.Unmarshal(encryptedData, &encryptedTrade)
	if err != nil {
		return Trade{}, err
	}

	return encryptedTrade, nil
}

func (ad *ArbitrageDetector) decryptTrade(encryptedTrade Trade) (Trade, error) {
	data, err := json.Marshal(encryptedTrade)
	if err != nil {
		return Trade{}, err
	}

	decryptedData, err := decrypt(data, ad.encryptionKey)
	if err != nil {
		return Trade{}, err
	}

	var trade Trade
	err = json.Unmarshal(decryptedData, &trade)
	if err != nil {
		return Trade{}, err
	}

	return trade, nil
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func createHash(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

func generateUniqueID(input string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(input), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(dk)
	return hex.EncodeToString(hash[:]), nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}
