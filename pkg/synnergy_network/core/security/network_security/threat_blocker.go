package security

import (
    "log"
    "sync"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    SaltSize = 16
    KeyLength = 32
    ArgonTime = 1
    ArgonMemory = 64 * 1024
    ArgonThreads = 4
    ScryptN = 16384
    ScryptR = 8
    ScryptP = 1
)

// ThreatBlocker manages blocking operations against detected threats.
type ThreatBlocker struct {
    blockedTransactions sync.Map // Thread-safe map to store blocked transaction IDs.
}

// BlockTransaction marks a transaction as blocked based on its ID.
func (tb *ThreatBlocker) BlockTransaction(transactionID string) {
    tb.blockedTransactions.Store(transactionID, true)
    log.Printf("Transaction %s has been blocked", transactionID)
}

// IsTransactionBlocked checks if a transaction is blocked.
func (tb *ThreatBlocker) IsTransactionBlocked(transactionID string) bool {
    _, blocked := tb.blockedTransactions.Load(transactionID)
    return blocked
}

// Example main function to demonstrate functionality.
func main() {
    blocker := &ThreatBlocker{}

    // Example transaction IDs to block
    blocker.BlockTransaction("tx1001")
    blocker.BlockTransaction("tx1002")

    // Check if specific transactions are blocked
    log.Printf("Is tx1001 blocked? %v", blocker.IsTransactionBlocked("tx1001"))
    log.Printf("Is tx1002 blocked? %v", blocker.IsTransactionBlocked("tx1002"))
    log.Printf("Is tx1003 blocked? %v", blocker.IsTransactionBlocked("tx1003"))
}

