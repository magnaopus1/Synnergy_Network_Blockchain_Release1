package doublespend

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "log"
    "sync"
    "time"

    "github.com/yourorg/yourproject/blockchain"
    "github.com/yourorg/yourproject/cryptography"
    "github.com/yourorg/yourproject/models"
    "github.com/yourorg/yourproject/network"
)

// DoubleSpendPreventionService provides mechanisms to detect and prevent double-spending
type DoubleSpendPreventionService struct {
    transactionPool map[string]*models.Transaction
    spentOutputs    map[string]bool
    mu              sync.Mutex
    blockchain      *blockchain.Blockchain
}

// NewDoubleSpendPreventionService initializes the service
func NewDoubleSpendPreventionService(bc *blockchain.Blockchain) *DoubleSpendPreventionService {
    return &DoubleSpendPreventionService{
        transactionPool: make(map[string]*models.Transaction),
        spentOutputs:    make(map[string]bool),
        blockchain:      bc,
    }
}

// AddTransaction adds a transaction to the pool after checking for double spending
func (dsps *DoubleSpendPreventionService) AddTransaction(tx *models.Transaction) error {
    dsps.mu.Lock()
    defer dsps.mu.Unlock()

    if dsps.isDoubleSpend(tx) {
        return errors.New("double spending detected")
    }

    txID := dsps.hashTransaction(tx)
    dsps.transactionPool[txID] = tx
    dsps.markOutputsAsSpent(tx)

    log.Printf("Transaction %s added to the pool", txID)
    return nil
}

// isDoubleSpend checks if the transaction is attempting to spend already spent outputs
func (dsps *DoubleSpendPreventionService) isDoubleSpend(tx *models.Transaction) bool {
    for _, input := range tx.Inputs {
        if dsps.spentOutputs[input.OutputID] {
            return true
        }
    }
    return false
}

// markOutputsAsSpent marks the outputs of a transaction as spent
func (dsps *DoubleSpendPreventionService) markOutputsAsSpent(tx *models.Transaction) {
    for _, input := range tx.Inputs {
        dsps.spentOutputs[input.OutputID] = true
    }
}

// hashTransaction hashes a transaction to generate a unique ID
func (dsps *DoubleSpendPreventionService) hashTransaction(tx *models.Transaction) string {
    txBytes := []byte(tx.String()) // Assuming the Transaction struct has a String() method
    hash := sha256.Sum256(txBytes)
    return hex.EncodeToString(hash[:])
}

// VerifyTransactionInclusion checks if a transaction is included in a block
func (dsps *DoubleSpendPreventionService) VerifyTransactionInclusion(txID string) bool {
    block, err := dsps.blockchain.GetBlockContainingTransaction(txID)
    if err != nil {
        log.Printf("Error verifying transaction inclusion: %v", err)
        return false
    }
    return block != nil
}

// MonitorTransactions monitors the network for potential double-spending attempts
func (dsps *DoubleSpendPreventionService) MonitorTransactions() {
    // Implement real-time monitoring and analysis of network transactions
    // Use cryptographic techniques and consensus algorithms to validate transactions
    for {
        // Placeholder: Real-time monitoring logic
        time.Sleep(5 * time.Second)
        log.Println("Monitoring transactions for double spending...")
    }
}

// ClearOldTransactions clears transactions from the pool after a certain period
func (dsps *DoubleSpendPreventionService) ClearOldTransactions(duration time.Duration) {
    dsps.mu.Lock()
    defer dsps.mu.Unlock()

    for txID, tx := range dsps.transactionPool {
        if time.Since(tx.Timestamp) > duration {
            delete(dsps.transactionPool, txID)
            log.Printf("Cleared old transaction: %s", txID)
        }
    }
}

// NotifyDoubleSpendAlert sends an alert if a double-spend is detected
func (dsps *DoubleSpendPreventionService) NotifyDoubleSpendAlert(tx *models.Transaction) {
    // Placeholder for sending alerts or notifications to the network or administrators
    log.Printf("Double spend detected for transaction: %s", tx.String())
}
