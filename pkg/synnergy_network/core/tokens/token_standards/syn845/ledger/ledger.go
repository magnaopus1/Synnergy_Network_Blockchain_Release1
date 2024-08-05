package ledger

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// LedgerEntry represents a single entry in the blockchain ledger
type LedgerEntry struct {
	EntryID      string    `json:"entry_id"`
	Timestamp    time.Time `json:"timestamp"`
	DebtID       string    `json:"debt_id"`
	Transaction  string    `json:"transaction"`
	Amount       float64   `json:"amount"`
	Balance      float64   `json:"balance"`
	Interest     float64   `json:"interest"`
	Principal    float64   `json:"principal"`
}

// Ledger manages all ledger entries for the SYN845 token standard
type Ledger struct {
	entries map[string]LedgerEntry
	mu      sync.Mutex
}

// NewLedger creates a new instance of Ledger
func NewLedger() *Ledger {
	return &Ledger{
		entries: make(map[string]LedgerEntry),
	}
}

// RecordEntry records a new entry in the ledger
func (l *Ledger) RecordEntry(debtID, transaction string, amount, balance, interest, principal float64) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entryID := generateEntryID()
	timestamp := time.Now()

	entry := LedgerEntry{
		EntryID:     entryID,
		Timestamp:   timestamp,
		DebtID:      debtID,
		Transaction: transaction,
		Amount:      amount,
		Balance:     balance,
		Interest:    interest,
		Principal:   principal,
	}

	l.entries[entryID] = entry
	err := saveLedgerEntryToStorage(entry)
	if err != nil {
		return "", err
	}

	return entryID, nil
}

// GetEntry retrieves a ledger entry by entry ID
func (l *Ledger) GetEntry(entryID string) (LedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.entries[entryID]
	if !exists {
		return LedgerEntry{}, errors.New("ledger entry not found")
	}

	return entry, nil
}

// GetEntriesByDebtID retrieves all ledger entries for a specific debt ID
func (l *Ledger) GetEntriesByDebtID(debtID string) ([]LedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var entries []LedgerEntry
	for _, entry := range l.entries {
		if entry.DebtID == debtID {
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no ledger entries found for the specified debt ID")
	}

	return entries, nil
}

// generateEntryID generates a unique ID for the ledger entry
func generateEntryID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-entry-id"
}

// saveLedgerEntryToStorage securely stores ledger entry data
func saveLedgerEntryToStorage(entry LedgerEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("ledger", entry.EntryID, encryptedData)
}

// deleteLedgerEntryFromStorage deletes ledger entry data from storage
func deleteLedgerEntryFromStorage(entryID string) error {
	return storage.Delete("ledger", entryID)
}
