package transaction

import (
	"errors"
	"sync"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// PrivateTransactionManager handles the lifecycle of private transactions.
type PrivateTransactionManager struct {
	sync.Mutex
	Blockchain    *blockchain.Blockchain
	TransactionDB map[string]*PrivateTransaction // Storage for private transactions
}

// NewPrivateTransactionManager creates a new instance of a private transaction manager.
func NewPrivateTransactionManager(bc *blockchain.Blockchain) *PrivateTransactionManager {
	return &PrivateTransactionManager{
		Blockchain:    bc,
		TransactionDB: make(map[string]*PrivateTransaction),
	}
}

// AddTransaction securely adds a new transaction to the blockchain.
func (ptm *PrivateTransactionManager) AddTransaction(tx *PrivateTransaction) error {
	ptm.Lock()
	defer ptm.Unlock()

	if _, exists := ptm.TransactionDB[tx.ID]; exists {
		return errors.New("transaction already exists")
	}

	encryptedData, err := EncryptTransactionData(tx.EncryptedData, encryption.GenerateKey())
	if err != nil {
		return err
	}

	tx.EncryptedData = encryptedData
	ptm.TransactionDB[tx.ID] = tx

	// Broadcast to network for validation and consensus
	ptm.Blockchain.BroadcastTransaction(tx)
	return nil
}

// GetTransaction retrieves a decrypted transaction by its ID.
func (ptm *PrivateTransactionManager) GetTransaction(id string, decryptionKey string) (*PrivateTransaction, error) {
	ptm.Lock()
	defer ptm.Unlock()

	tx, exists := ptm.TransactionDB[id]
	if !exists {
		return nil, errors.New("transaction not found")
	}

	decryptedData, err := DecryptTransactionData(tx.EncryptedData, decryptionKey)
	if err != nil {
		return nil, err
	}

	tx.EncryptedData = decryptedData
	return tx, nil
}

// ValidateTransaction checks the validity of a transaction using security parameters.
func (ptm *PrivateTransactionManager) ValidateTransaction(tx *PrivateTransaction) bool {
	return tx.VerifyTransactionSignature() && encryption.ValidateHash(tx.EncryptedData)
}

// ProcessTransactions processes and finalizes transactions, updating the blockchain state.
func (ptm *PrivateTransactionManager) ProcessTransactions() {
	for _, tx := range ptm.TransactionDB {
		if ptm.ValidateTransaction(tx) {
			ptm.Blockchain.AddTransactionToBlock(tx)
		} else {
			delete(ptm.TransactionJournals, tx.ID) // Remove invalid transaction
		}
	}
}

// init initializes necessary components and settings for transaction encryption.
func init() {
	encryption.SetupEncryption("AES", "Scrypt", "Argon2")
}
