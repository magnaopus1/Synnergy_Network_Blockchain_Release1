package arbitrage_tools

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
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

type RiskParameters struct {
	MaximumExposure float64 `json:"maximum_exposure"`
	MinimumProfit   float64 `json:"minimum_profit"`
	StopLoss        float64 `json:"stop_loss"`
}

type RiskManagement struct {
	sync.Mutex
	riskParameters RiskParameters
	openPositions  map[string]ArbitrageOpportunity
	encryptionKey  string
}

func NewRiskManagement(encryptionKey string, riskParams RiskParameters) *RiskManagement {
	return &RiskManagement{
		riskParameters: riskParams,
		openPositions:  make(map[string]ArbitrageOpportunity),
		encryptionKey:  encryptionKey,
	}
}

func (rm *RiskManagement) ValidateOpportunity(opportunity ArbitrageOpportunity) (bool, error) {
	rm.Lock()
	defer rm.Unlock()

	encryptedOpportunity, err := rm.encryptOpportunity(opportunity)
	if err != nil {
		return false, err
	}

	if opportunity.Profit < rm.riskParameters.MinimumProfit {
		return false, fmt.Errorf("profit below minimum threshold")
	}

	exposure := opportunity.BuyTrade.Price * opportunity.BuyTrade.Amount
	if exposure > rm.riskParameters.MaximumExposure {
		return false, fmt.Errorf("exposure exceeds maximum threshold")
	}

	opportunityID, err := generateUniqueID(fmt.Sprintf("%v", opportunity))
	if err != nil {
		return false, err
	}

	rm.openPositions[opportunityID] = encryptedOpportunity
	return true, nil
}

func (rm *RiskManagement) MonitorOpenPositions() {
	for {
		rm.Lock()
		for id, position := range rm.openPositions {
			decryptedPosition, err := rm.decryptOpportunity(position)
			if err != nil {
				log.Println("Error decrypting position:", err)
				continue
			}

			if rm.checkStopLoss(decryptedPosition) {
				log.Println("Stop loss triggered for position:", id)
				delete(rm.openPositions, id)
			}
		}
		rm.Unlock()
		time.Sleep(1 * time.Minute)
	}
}

func (rm *RiskManagement) checkStopLoss(position ArbitrageOpportunity) bool {
	currentPrice := rm.getCurrentMarketPrice(position.BuyTrade.Pair)
	if currentPrice == 0 {
		return false
	}

	loss := (position.BuyTrade.Price - currentPrice) * position.BuyTrade.Amount
	return loss >= rm.riskParameters.StopLoss
}

func (rm *RiskManagement) getCurrentMarketPrice(pair string) float64 {
	// Placeholder for real market data fetching
	return 0
}

func (rm *RiskManagement) encryptOpportunity(opportunity ArbitrageOpportunity) (ArbitrageOpportunity, error) {
	data, err := json.Marshal(opportunity)
	if err != nil {
		return ArbitrageOpportunity{}, err
	}

	encryptedData, err := encrypt(data, rm.encryptionKey)
	if err != nil {
		return ArbitrageOpportunity{}, err
	}

	var encryptedOpportunity ArbitrageOpportunity
	err = json.Unmarshal(encryptedData, &encryptedOpportunity)
	if err != nil {
		return ArbitrageOpportunity{}, err
	}

	return encryptedOpportunity, nil
}

func (rm *RiskManagement) decryptOpportunity(encryptedOpportunity ArbitrageOpportunity) (ArbitrageOpportunity, error) {
	data, err := json.Marshal(encryptedOpportunity)
	if err != nil {
		return ArbitrageOpportunity{}, err
	}

	decryptedData, err := decrypt(data, rm.encryptionKey)
	if err != nil {
		return ArbitrageOpportunity{}, err
	}

	var opportunity ArbitrageOpportunity
	err = json.Unmarshal(decryptedData, &opportunity)
	if err != nil {
		return ArbitrageOpportunity{}, err
	}

	return opportunity, nil
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
