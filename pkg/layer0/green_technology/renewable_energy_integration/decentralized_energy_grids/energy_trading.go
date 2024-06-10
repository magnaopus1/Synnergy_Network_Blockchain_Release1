package decentralized_energy_grids

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"golang.org/x/crypto/scrypt"
)

// EnergyTrade represents a trade of energy between two users.
type EnergyTrade struct {
	TradeID         string `json:"trade_id"`
	SellerID        string `json:"seller_id"`
	BuyerID         string `json:"buyer_id"`
	EnergyAmount    string `json:"energy_amount"`
	TradeTimestamp  string `json:"trade_timestamp"`
	Price           string `json:"price"`
	TradeStatus     string `json:"trade_status"`
	EncryptedEnergy string `json:"encrypted_energy"`
}

// GenerateSalt generates a new salt for encryption.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey derives a key from a password and a salt using scrypt.
func DeriveKey(password string, salt []byte) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// EncryptData encrypts the given data using AES with the derived key.
func EncryptData(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given encrypted data using AES with the derived key.
func DecryptData(encryptedData string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
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

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// CreateEnergyTrade creates a new energy trade on the blockchain.
func CreateEnergyTrade(tradeID, sellerID, buyerID, energyAmount, price, password string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedEnergy, err := EncryptData(energyAmount, key)
	if err != nil {
		return err
	}

	trade := EnergyTrade{
		TradeID:         tradeID,
		SellerID:        sellerID,
		BuyerID:         buyerID,
		EnergyAmount:    energyAmount,
		TradeTimestamp:  time.Now().Format(time.RFC3339),
		Price:           price,
		TradeStatus:     "Pending",
		EncryptedEnergy: encryptedEnergy,
	}

	tradeJSON, err := json.Marshal(trade)
	if err != nil {
		return err
	}

	return blockchain.PutState(tradeID, tradeJSON)
}

// GetEnergyTrade retrieves and decrypts an energy trade from the blockchain.
func GetEnergyTrade(tradeID, password string) (*EnergyTrade, error) {
	tradeJSON, err := blockchain.GetState(tradeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if tradeJSON == nil {
		return nil, fmt.Errorf("the trade %s does not exist", tradeID)
	}

	var trade EnergyTrade
	err = json.Unmarshal(tradeJSON, &trade)
	if err != nil {
		return nil, err
	}

	salt := []byte(trade.TradeID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	energyAmount, err := DecryptData(trade.EncryptedEnergy, key)
	if err != nil {
		return nil, err
	}

	trade.EnergyAmount = energyAmount
	return &trade, nil
}

// UpdateEnergyTrade updates an existing energy trade on the blockchain.
func UpdateEnergyTrade(tradeID, sellerID, buyerID, energyAmount, price, tradeStatus, password string) error {
	exists, err := EnergyTradeExists(tradeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the trade %s does not exist", tradeID)
	}

	salt := []byte(tradeID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedEnergy, err := EncryptData(energyAmount, key)
	if err != nil {
		return err
	}

	trade := EnergyTrade{
		TradeID:         tradeID,
		SellerID:        sellerID,
		BuyerID:         buyerID,
		EnergyAmount:    energyAmount,
		TradeTimestamp:  time.Now().Format(time.RFC3339),
		Price:           price,
		TradeStatus:     tradeStatus,
		EncryptedEnergy: encryptedEnergy,
	}

	tradeJSON, err := json.Marshal(trade)
	if err != nil {
		return err
	}

	return blockchain.PutState(tradeID, tradeJSON)
}

// DeleteEnergyTrade deletes an energy trade from the blockchain.
func DeleteEnergyTrade(tradeID string) error {
	exists, err := EnergyTradeExists(tradeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the trade %s does not exist", tradeID)
	}

	return blockchain.DelState(tradeID)
}

// EnergyTradeExists checks if an energy trade exists on the blockchain.
func EnergyTradeExists(tradeID string) (bool, error) {
	tradeJSON, err := blockchain.GetState(tradeID)
	if err != nil {
		return false, fmt.Errorf("failed to read from blockchain: %v", err)
	}

	return tradeJSON != nil, nil
}

// CompleteEnergyTrade completes a pending energy trade.
func CompleteEnergyTrade(tradeID, password string) error {
	trade, err := GetEnergyTrade(tradeID, password)
	if err != nil {
		return err
	}

	trade.TradeStatus = "Completed"
	return UpdateEnergyTrade(trade.TradeID, trade.SellerID, trade.BuyerID, trade.EnergyAmount, trade.Price, trade.TradeStatus, password)
}

// ListAllTrades lists all energy trades.
func ListAllTrades() ([]EnergyTrade, error) {
	// Placeholder for a method to list all trades.
	// This would typically involve querying the blockchain ledger for all trade records.
	// For now, we return an empty list.
	return []EnergyTrade{}, nil
}
