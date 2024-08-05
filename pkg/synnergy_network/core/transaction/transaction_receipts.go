package transaction

import (
	"errors"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"encoding/pem"
	"encoding/hex"
)


// CreateReceipt creates a new transaction receipt.
func (rm *common.ReceiptManager) CreateTransactionReceipt(txID, sender, receiver string, amount float64, tokenID, tokenStandard string) (*common.Receipt, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	receipt := &common.Receipt{
		ID:            generateReceiptID(txID),
		TxID:          txID,
		Timestamp:     time.Now(),
		Amount:        amount,
		Sender:        sender,
		Receiver:      receiver,
		Status:        "Pending",
		TokenID:       tokenID,
		TokenStandard: tokenStandard,
	}

	encryptedData, err := encryptData(receipt, rm.encryptionKey)
	if err != nil {
		return nil, err
	}
	receipt.EncryptedData = encryptedData

	receipt.Signature, err = signData(receipt)
	if err != nil {
		return nil, err
	}

	rm.receipts[receipt.ID] = receipt
	return receipt, nil
}

// GetReceipt retrieves a transaction receipt by ID.
func (rm *common.ReceiptManager) GetTransactionReceiptByID(receiptID string) (*common.Receipt, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	receipt, exists := rm.receipts[receiptID]
	if !exists {
		return nil, errors.New("receipt not found")
	}

	decryptedData, err := decryptData(receipt.EncryptedData, rm.encryptionKey)
	if err != nil {
		return nil, err
	}
	receipt = decryptedData.(*common.Receipt)

	return receipt, nil
}

// UpdateReceiptStatus updates the status of a transaction receipt.
func (rm *common.ReceiptManager) UpdateTransactionReceiptStatus(receiptID, status string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	receipt, exists := rm.receipts[receiptID]
	if !exists {
		return errors.New("receipt not found")
	}

	receipt.Status = status

	encryptedData, err := encryptData(receipt, rm.encryptionKey)
	if err != nil {
		return err
	}
	receipt.EncryptedData = encryptedData

	receipt.Signature, err = signData(receipt)
	if err != nil {
		return err
	}

	rm.receipts[receipt.ID] = receipt
	return nil
}

// ValidateReceiptSignature validates the signature of a transaction receipt.
func ValidateTransactionReceiptSignature(receipt *common.Receipt) bool {
	return validateSignature(receipt.Signature, receipt)
}

// RequestChargeback creates a new chargeback request.
func (rm *common.ReceiptManager) RequestTransactionChargeback(originalTxID, requester, reason string, amount float64, tokenID, tokenStandard string) (*common.Chargeback, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	chargeback := &common.Chargeback{
		ID:            generateChargebackID(originalTxID),
		OriginalTxID:  originalTxID,
		Timestamp:     time.Now(),
		Amount:        amount,
		Requester:     requester,
		Status:        "Pending",
		Reason:        reason,
		TokenID:       tokenID,
		TokenStandard: tokenStandard,
	}

	encryptedData, err := encryptData(chargeback, rm.encryptionKey)
	if err != nil {
		return nil, err
	}
	chargeback.EncryptedData = encryptedData

	chargeback.Signature, err = signData(chargeback)
	if err != nil {
		return nil, err
	}

	rm.chargebacks[chargeback.ID] = chargeback
	return chargeback, nil
}

// GetChargeback retrieves a chargeback request by ID.
func (rm *common.ReceiptManager) GetChargebackRequest(chargebackID string) (*common.Chargeback, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	chargeback, exists := rm.chargebacks[chargebackID]
	if !exists {
		return nil, errors.New("chargeback not found")
	}

	decryptedData, err := decryptData(chargeback.EncryptedData, rm.encryptionKey)
	if err != nil {
		return nil, err
	}
	chargeback = decryptedData.(*common.Chargeback)

	return chargeback, nil
}

// UpdateChargebackStatus updates the status of a chargeback request.
func (rm *common.ReceiptManager) UpdateChargebackStatus(chargebackID, status string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	chargeback, exists := rm.chargebacks[chargebackID]
	if !exists {
		return errors.New("chargeback not found")
	}

	chargeback.Status = status

	encryptedData, err := encryptData(chargeback, rm.encryptionKey)
	if err != nil {
		return err
	}
	chargeback.EncryptedData = encryptedData

	chargeback.Signature, err = signData(chargeback)
	if err != nil {
		return err
	}

	rm.chargebacks[chargeback.ID] = chargeback
	return nil
}

// ValidateChargebackSignature validates the signature of a chargeback request.
func ValidateChargebackSignature(chargeback *common.Chargeback) bool {
	return validateSignature(chargeback.Signature, chargeback)
}

// GenerateTransactionReceipt generates a new transaction receipt.
func (rm *common.ReceiptManager) GenerateTransactionReceipt(txID, status, blockHash string) (*common.TransactionReceipt, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	receipt := &common.TransactionReceipt{
		ID:            generateReceiptID(txID),
		TransactionID: txID,
		Timestamp:     time.Now(),
		Status:        status,
		BlockHash:     blockHash,
	}

	encryptedData, err := encryptData(receipt, rm.encryptionKey)
	if err != nil {
		return nil, err
	}
	receipt.EncryptedData = encryptedData

	receipt.ValidatorSign, err = signData(receipt)
	if err != nil {
		return nil, err
	}

	rm.transactionReceipts[receipt.ID] = receipt
	return receipt, nil
}

// GetTransactionReceipt retrieves a transaction receipt by ID.
func (rm *common.ReceiptManager) GetTransactionReceiptByID(receiptID string) (*common.TransactionReceipt, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	receipt, exists := rm.transactionReceipts[receiptID]
	if !exists {
		return nil, errors.New("receipt not found")
	}

	decryptedData, err := decryptData(receipt.EncryptedData, rm.encryptionKey)
	if err != nil {
		return nil, err
	}
	receipt = decryptedData.(*common.TransactionReceipt)

	return receipt, nil
}

// ValidateTransactionReceiptSignature validates the signature of a transaction receipt.
func ValidateTransactionReceiptSignature(receipt *common.TransactionReceipt) bool {
	return validateSignature(receipt.ValidatorSign, receipt)
}

// Helper functions

func generateReceiptID(txID string) string {
	hasher := sha256.New()
	hasher.Write([]byte(txID))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateChargebackID(txID string) string {
	hasher := sha256.New()
	hasher.Write([]byte(txID))
	return hex.EncodeToString(hasher.Sum(nil))
}

