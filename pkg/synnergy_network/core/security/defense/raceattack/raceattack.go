package raceattack

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// RaceAttackMonitor monitors for potential race attacks in the network
type RaceAttackMonitor struct {
    mu               sync.Mutex
    confirmedTxs     map[string]struct{}
    pendingTxs       map[string]time.Time
    syncTolerance    time.Duration
    alertChannel     chan string
    preventionAction func(txID string)
}

// NewRaceAttackMonitor initializes a new RaceAttackMonitor
func NewRaceAttackMonitor(syncTolerance time.Duration, preventionAction func(txID string)) *RaceAttackMonitor {
    return &RaceAttackMonitor{
        confirmedTxs:     make(map[string]struct{}),
        pendingTxs:       make(map[string]time.Time),
        syncTolerance:    syncTolerance,
        alertChannel:     make(chan string, 100),
        preventionAction: preventionAction,
    }
}

// MonitorTransaction adds a transaction to the monitoring list
func (ram *RaceAttackMonitor) MonitorTransaction(txID string) error {
    ram.mu.Lock()
    defer ram.mu.Unlock()

    if _, exists := ram.confirmedTxs[txID]; exists {
        return errors.New("transaction already confirmed")
    }

    if _, exists := ram.pendingTxs[txID]; exists {
        return errors.New("transaction already pending")
    }

    ram.pendingTxs[txID] = time.Now()
    return nil
}

// ConfirmTransaction confirms a transaction and checks for race conditions
func (ram *RaceAttackMonitor) ConfirmTransaction(txID string) error {
    ram.mu.Lock()
    defer ram.mu.Unlock()

    if _, exists := ram.confirmedTxs[txID]; exists {
        return errors.New("transaction already confirmed")
    }

    if timestamp, exists := ram.pendingTxs[txID]; exists {
        if time.Since(timestamp) > ram.syncTolerance {
            ram.alertChannel <- txID
            ram.preventionAction(txID)
            return fmt.Errorf("possible race attack detected for transaction %s", txID)
        }
        delete(ram.pendingTxs, txID)
    }

    ram.confirmedTxs[txID] = struct{}{}
    return nil
}

// RemoveStaleTransactions removes old transactions from the pending list
func (ram *RaceAttackMonitor) RemoveStaleTransactions() {
    ram.mu.Lock()
    defer ram.mu.Unlock()

    threshold := time.Now().Add(-ram.syncTolerance)
    for txID, timestamp := range ram.pendingTxs {
        if timestamp.Before(threshold) {
            delete(ram.pendingTxs, txID)
        }
    }
}

// GenerateTxID generates a unique transaction ID using SHA-256
func GenerateTxID(data string) string {
    hash := sha256.New()
    hash.Write([]byte(data))
    return hex.EncodeToString(hash.Sum(nil))
}

// ListenForAlerts listens for alerts of potential race attacks
func (ram *RaceAttackMonitor) ListenForAlerts() <-chan string {
    return ram.alertChannel
}

// Example prevention action function
func ExamplePreventionAction(txID string) {
    fmt.Printf("Taking action to prevent race attack for transaction: %s\n", txID)
    // Implement prevention logic here, e.g., invalidating conflicting transactions
}
