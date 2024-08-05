package management

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/assets"
	"github.com/synnergy_network/utils"
)

// MultiSignatureSecurityManager manages multi-signature security for high-value transactions.
type MultiSignatureSecurityManager struct {
	mu                sync.RWMutex
	multiSigTxStore   map[string]*MultiSignatureTransaction
	signatureStore    map[string]map[string]bool
	requiredSignatures int
}

// MultiSignatureTransaction represents a transaction that requires multiple signatures.
type MultiSignatureTransaction struct {
	ID          string
	TokenID     string
	From        string
	To          string
	Amount      uint64
	Signatures  map[string]bool
	IsCompleted bool
}

// NewMultiSignatureSecurityManager initializes a new MultiSignatureSecurityManager instance.
func NewMultiSignatureSecurityManager(requiredSignatures int) *MultiSignatureSecurityManager {
	return &MultiSignatureSecurityManager{
		multiSigTxStore:   make(map[string]*MultiSignatureTransaction),
		signatureStore:    make(map[string]map[string]bool),
		requiredSignatures: requiredSignatures,
	}
}

// CreateMultiSignatureTransaction creates a new multi-signature transaction.
func (msm *MultiSignatureSecurityManager) CreateMultiSignatureTransaction(tokenID, from, to string, amount uint64) (string, error) {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	// Validate inputs
	if tokenID == "" || from == "" || to == "" || amount == 0 {
		return "", errors.New("invalid transaction parameters")
	}

	// Generate a unique transaction ID
	txID := uuid.New().String()

	// Create the multi-signature transaction
	tx := &MultiSignatureTransaction{
		ID:         txID,
		TokenID:    tokenID,
		From:       from,
		To:         to,
		Amount:     amount,
		Signatures: make(map[string]bool),
	}

	// Store the transaction
	msm.multiSigTxStore[txID] = tx
	msm.signatureStore[txID] = make(map[string]bool)

	return txID, nil
}

// SignTransaction allows a user to sign a multi-signature transaction.
func (msm *MultiSignatureSecurityManager) SignTransaction(txID, userID string) error {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	// Validate transaction existence
	tx, exists := msm.multiSigTxStore[txID]
	if !exists {
		return errors.New("transaction not found")
	}

	// Validate if user has already signed
	if _, signed := msm.signatureStore[txID][userID]; signed {
		return errors.New("user has already signed this transaction")
	}

	// Add the user's signature
	msm.signatureStore[txID][userID] = true
	tx.Signatures[userID] = true

	// Check if the required number of signatures is reached
	if len(tx.Signatures) >= msm.requiredSignatures {
		tx.IsCompleted = true
	}

	return nil
}

// ExecuteTransaction executes a multi-signature transaction once the required number of signatures is reached.
func (msm *MultiSignatureSecurityManager) ExecuteTransaction(txID string, executeFunc func(tx *MultiSignatureTransaction) error) error {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	// Validate transaction existence
	tx, exists := msm.multiSigTxStore[txID]
	if !exists {
		return errors.New("transaction not found")
	}

	// Check if the transaction has the required number of signatures
	if len(tx.Signatures) < msm.requiredSignatures {
		return errors.New("not enough signatures to execute the transaction")
	}

	// Execute the transaction using the provided executeFunc
	if err := executeFunc(tx); err != nil {
		return err
	}

	// Mark the transaction as completed and remove it from the store
	tx.IsCompleted = true
	delete(msm.multiSigTxStore, txID)
	delete(msm.signatureStore, txID)

	return nil
}

// GetTransaction retrieves a multi-signature transaction by ID.
func (msm *MultiSignatureSecurityManager) GetTransaction(txID string) (*MultiSignatureTransaction, error) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	tx, exists := msm.multiSigTxStore[txID]
	if !exists {
		return nil, errors.New("transaction not found")
	}

	return tx, nil
}

// GetPendingTransactions lists all pending multi-signature transactions.
func (msm *MultiSignatureSecurityManager) GetPendingTransactions() ([]*MultiSignatureTransaction, error) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	var pendingTransactions []*MultiSignatureTransaction
	for _, tx := range msm.multiSigTxStore {
		if !tx.IsCompleted {
			pendingTransactions = append(pendingTransactions, tx)
		}
	}

	return pendingTransactions, nil
}

// EncryptTransaction encrypts a multi-signature transaction using a specified encryption technique.
func (msm *MultiSignatureSecurityManager) EncryptTransaction(tx *MultiSignatureTransaction, passphrase string) (string, error) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	// Serialize transaction to JSON
	jsonData, err := utils.ToJSON(tx)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransaction decrypts a multi-signature transaction using a specified decryption technique.
func (msm *MultiSignatureSecurityManager) DecryptTransaction(encryptedData, passphrase string) (*MultiSignatureTransaction, error) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	// Deserialize JSON data to transaction
	var tx MultiSignatureTransaction
	err = utils.FromJSON(decryptedData, &tx)
	if err != nil {
		return nil, err
	}

	return &tx, nil
}
