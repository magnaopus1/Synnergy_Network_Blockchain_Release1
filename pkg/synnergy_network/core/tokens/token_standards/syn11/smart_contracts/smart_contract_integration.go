package smart_contracts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"time"
)

// SmartContractIntegration manages the integration and execution of smart contracts.
type SmartContractIntegration struct {
	contracts map[string]*SmartContract
}

// SmartContract represents a generic smart contract with essential fields and methods.
type SmartContract struct {
	ID             string
	GiltID         string
	Principal      float64
	CouponRate     float64
	MaturityDate   time.Time
	LastUpdate     time.Time
	InterestAccrued float64
	CouponPaid     float64
	EncryptionKey  string
}

// NewSmartContractIntegration initializes a new SmartContractIntegration.
func NewSmartContractIntegration() *SmartContractIntegration {
	return &SmartContractIntegration{
		contracts: make(map[string]*SmartContract),
	}
}

// CreateSmartContract creates and registers a new smart contract.
func (sci *SmartContractIntegration) CreateSmartContract(giltID string, principal, couponRate float64, maturityDate time.Time) (*SmartContract, error) {
	if principal <= 0 || couponRate < 0 {
		return nil, errors.New("invalid principal or coupon rate")
	}

	id := generateUniqueID(giltID)
	encryptionKey := generateEncryptionKey(giltID)

	contract := &SmartContract{
		ID:            id,
		GiltID:        giltID,
		Principal:     principal,
		CouponRate:    couponRate,
		MaturityDate:  maturityDate,
		LastUpdate:    time.Now(),
		EncryptionKey: encryptionKey,
	}

	sci.contracts[id] = contract
	return contract, nil
}

// ExecuteContract executes a smart contract by calculating accrued interest and distributing coupon payments.
func (sci *SmartContractIntegration) ExecuteContract(contractID string) error {
	contract, exists := sci.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	if contract.MaturityDate.Before(time.Now()) {
		return errors.New("contract has matured, no further actions required")
	}

	interestAccrued, err := calculateAccruedInterest(contract)
	if err != nil {
		return err
	}

	contract.InterestAccrued += interestAccrued
	contract.CouponPaid += interestAccrued
	contract.LastUpdate = time.Now()

	logContractExecution(contractID, interestAccrued)
	return nil
}

// TerminateContract terminates a smart contract and clears associated data.
func (sci *SmartContractIntegration) TerminateContract(contractID string) error {
	_, exists := sci.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	delete(sci.contracts, contractID)
	return nil
}

// EncryptData encrypts sensitive data using the contract's encryption key.
func (sc *SmartContract) EncryptData(plainText string) (string, error) {
	block, err := aes.NewCipher([]byte(sc.EncryptionKey))
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))

	return hex.EncodeToString(cipherText), nil
}

// DecryptData decrypts encrypted data using the contract's encryption key.
func (sc *SmartContract) DecryptData(cipherText string) (string, error) {
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(sc.EncryptionKey))
	if err != nil {
		return "", err
	}

	if len(cipherTextBytes) < aes.BlockSize {
		return "", errors.New("cipher text too short")
	}

	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherTextBytes, cipherTextBytes)

	return string(cipherTextBytes), nil
}

// generateUniqueID generates a unique identifier for a smart contract.
func generateUniqueID(giltID string) string {
	hash := sha256.New()
	hash.Write([]byte(giltID + time.Now().String()))
	return hex.EncodeToString(hash.Sum(nil))
}

// generateEncryptionKey generates an encryption key for the smart contract.
func generateEncryptionKey(giltID string) string {
	hash := sha256.New()
	hash.Write([]byte(giltID + time.Now().String()))
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

// calculateAccruedInterest calculates the interest accrued since the last update.
func calculateAccruedInterest(contract *SmartContract) (float64, error) {
	timeElapsed := time.Since(contract.LastUpdate)
	annualInterest := contract.Principal * (contract.CouponRate / 100)
	accruedInterest := annualInterest * (float64(timeElapsed.Hours()) / (365 * 24))
	return accruedInterest, nil
}

// logContractExecution logs the execution details of a smart contract.
func logContractExecution(contractID string, amount float64) {
	log.Printf("Smart contract %s executed, interest accrued: %f", contractID, amount)
}
