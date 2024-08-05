package transactions

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "time"
    "sync"
    "golang.org/x/crypto/scrypt"
)

// TransactionValidationService provides methods to validate transactions
type TransactionValidationService struct {
    mu            sync.RWMutex
    validatedTxs  map[string]Transaction
    pendingTxs    map[string]Transaction
}

// NewTransactionValidationService creates a new TransactionValidationService
func NewTransactionValidationService() *TransactionValidationService {
    return &TransactionValidationService{
        validatedTxs: make(map[string]Transaction),
        pendingTxs:   make(map[string]Transaction),
    }
}

// ValidateTransaction validates a transaction and adds it to the validated pool if valid
func (tvs *TransactionValidationService) ValidateTransaction(tx Transaction) error {
    tvs.mu.Lock()
    defer tvs.mu.Unlock()

    if err := validateTransactionFields(tx); err != nil {
        return err
    }

    if err := validateTransactionSignature(tx); err != nil {
        return err
    }

    if err := checkTransactionHistory(tx); err != nil {
        return err
    }

    tvs.validatedTxs[tx.ID] = tx
    return nil
}

// validateTransactionFields validates the basic fields of a transaction
func validateTransactionFields(tx Transaction) error {
    if tx.Sender == "" || tx.Receiver == "" || tx.TokenID == "" || tx.Amount == 0 {
        return errors.New("invalid transaction fields")
    }
    if time.Since(tx.Timestamp) > 24*time.Hour {
        return errors.New("transaction timestamp is too old")
    }
    return nil
}

// validateTransactionSignature validates the transaction signature
func validateTransactionSignature(tx Transaction) error {
    data := tx.Sender + tx.Receiver + tx.TokenID + string(tx.Amount) + tx.Timestamp.String()
    salt := make([]byte, 16)
    derivedKey, err := scrypt.Key([]byte(data), salt, 16384, 8, 1, 32)
    if err != nil {
        return err
    }

    if tx.Signature != hex.EncodeToString(derivedKey) {
        return errors.New("invalid transaction signature")
    }
    return nil
}

// checkTransactionHistory checks if a similar transaction exists in the history
func checkTransactionHistory(tx Transaction) error {
    // This is a placeholder for a function that would check the blockchain or ledger
    // for existing transactions with the same ID or similar parameters
    // return nil if no such transaction exists, otherwise return an error
    return nil
}

// IsValid checks if a transaction is valid
func (tvs *TransactionValidationService) IsValid(txID string) (bool, error) {
    tvs.mu.RLock()
    defer tvs.mu.RUnlock()

    _, exists := tvs.validatedTxs[txID]
    if !exists {
        return false, errors.New("transaction not validated")
    }
    return true, nil
}

// InvalidateTransaction removes a transaction from the validated pool
func (tvs *TransactionValidationService) InvalidateTransaction(txID string) error {
    tvs.mu.Lock()
    defer tvs.mu.Unlock()

    if _, exists := tvs.validatedTxs[txID]; !exists {
        return errors.New("transaction not found")
    }

    delete(tvs.validatedTxs, txID)
    return nil
}

// ListValidatedTransactions lists all validated transactions
func (tvs *TransactionValidationService) ListValidatedTransactions() []Transaction {
    tvs.mu.RLock()
    defer tvs.mu.RUnlock()

    transactions := make([]Transaction, 0, len(tvs.validatedTxs))
    for _, tx := range tvs.validatedTxs {
        transactions = append(transactions, tx)
    }

    return transactions
}

// hashTransaction computes the hash of a transaction
func hashTransaction(tx Transaction) (string, error) {
    data := tx.Sender + tx.Receiver + tx.TokenID + string(tx.Amount) + tx.Timestamp.String()
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:]), nil
}

// IsDuplicate checks if a transaction is a duplicate
func (tvs *TransactionValidationService) IsDuplicate(tx Transaction) (bool, error) {
    txHash, err := hashTransaction(tx)
    if err != nil {
        return false, err
    }

    tvs.mu.RLock()
    defer tvs.mu.RUnlock()

    for _, validatedTx := range tvs.validatedTxs {
        validatedTxHash, err := hashTransaction(validatedTx)
        if err != nil {
            return false, err
        }
        if txHash == validatedTxHash {
            return true, nil
        }
    }

    return false, nil
}
