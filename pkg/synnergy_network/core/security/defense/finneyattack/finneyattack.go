package finneyattack

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "log"
    "sync"
    "time"

    "github.com/yourorg/yourproject/blockchain"
    "github.com/yourorg/yourproject/models"
)

// FinneyAttackPreventionService provides methods to detect and prevent Finney attacks
type FinneyAttackPreventionService struct {
    recentBlocks  map[string]*models.Block
    mu            sync.Mutex
    blockchain    *blockchain.Blockchain
}

// NewFinneyAttackPreventionService initializes a new FinneyAttackPreventionService
func NewFinneyAttackPreventionService(bc *blockchain.Blockchain) *FinneyAttackPreventionService {
    return &FinneyAttackPreventionService{
        recentBlocks: make(map[string]*models.Block),
        blockchain:   bc,
    }
}

// AddRecentBlock adds a recently mined block to the monitoring list
func (faps *FinneyAttackPreventionService) AddRecentBlock(block *models.Block) {
    faps.mu.Lock()
    defer faps.mu.Unlock()

    blockID := faps.hashBlock(block)
    faps.recentBlocks[blockID] = block

    // Clean up old blocks beyond a certain threshold
    if len(faps.recentBlocks) > 100 {
        faps.cleanupOldBlocks()
    }
}

// hashBlock hashes a block to generate a unique identifier
func (faps *FinneyAttackPreventionService) hashBlock(block *models.Block) string {
    blockBytes := []byte(block.String()) // Assuming the Block struct has a String() method
    hash := sha256.Sum256(blockBytes)
    return hex.EncodeToString(hash[:])
}

// DetectDoubleSpend checks for potential double-spending by comparing transaction inputs against recent blocks
func (faps *FinneyAttackPreventionService) DetectDoubleSpend(tx *models.Transaction) error {
    faps.mu.Lock()
    defer faps.mu.Unlock()

    for _, block := range faps.recentBlocks {
        for _, txInBlock := range block.Transactions {
            if faps.isDoubleSpend(tx, txInBlock) {
                faps.alert(tx, txInBlock)
                return errors.New("potential Finney attack detected: double-spending attempt")
            }
        }
    }

    return nil
}

// isDoubleSpend checks if two transactions are attempting to spend the same outputs
func (faps *FinneyAttackPreventionService) isDoubleSpend(tx1, tx2 *models.Transaction) bool {
    spentOutputs := make(map[string]bool)
    for _, input := range tx1.Inputs {
        spentOutputs[input.OutputID] = true
    }

    for _, input := range tx2.Inputs {
        if spentOutputs[input.OutputID] {
            return true
        }
    }

    return false
}

// alert sends an alert if a double-spending attempt is detected
func (faps *FinneyAttackPreventionService) alert(tx, conflictingTx *models.Transaction) {
    // Implement alert mechanism (e.g., logging, notifying network administrators)
    log.Printf("Alert: Double-spending attempt detected. Transaction: %s conflicts with %s", tx.String(), conflictingTx.String())
}

// cleanupOldBlocks removes blocks that are no longer recent
func (faps *FinneyAttackPreventionService) cleanupOldBlocks() {
    currentTimestamp := time.Now()
    for blockID, block := range faps.recentBlocks {
        if currentTimestamp.Sub(block.Timestamp) > 5*time.Minute {
            delete(faps.recentBlocks, blockID)
            log.Printf("Removed old block: %s", blockID)
        }
    }
}

// MonitorNetwork monitors the network for suspicious activities related to Finney attacks
func (faps *FinneyAttackPreventionService) MonitorNetwork() {
    // Implement network monitoring logic
    // This could include analyzing network traffic, tracking the propagation of transactions, etc.
    log.Println("Monitoring network for potential Finney attacks...")
    for {
        // Placeholder: Real-time monitoring logic
        time.Sleep(10 * time.Second)
    }
}
