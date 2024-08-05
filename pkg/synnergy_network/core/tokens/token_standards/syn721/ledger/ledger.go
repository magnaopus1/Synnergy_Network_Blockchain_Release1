package ledger

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/tokens/token_standards/syn721/assets"
)

// LedgerEntry represents a ledger entry for a token transfer
type LedgerEntry struct {
	TokenID     string
	From        string
	To          string
	Timestamp   time.Time
	Transaction string
}

// TokenLedger manages the ledger entries for SYN721 tokens
type TokenLedger struct {
	entries []LedgerEntry
	mutex   sync.Mutex
}

// NewTokenLedger initializes a new TokenLedger
func NewTokenLedger() *TokenLedger {
	return &TokenLedger{
		entries: make([]LedgerEntry, 0),
	}
}

// AddEntry adds a new entry to the ledger
func (tl *TokenLedger) AddEntry(tokenID, from, to, transaction string) {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	entry := LedgerEntry{
		TokenID:     tokenID,
		From:        from,
		To:          to,
		Timestamp:   time.Now(),
		Transaction: transaction,
	}

	tl.entries = append(tl.entries, entry)
}

// GetEntries retrieves all ledger entries
func (tl *TokenLedger) GetEntries() []LedgerEntry {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	return tl.entries
}

// GetEntriesByTokenID retrieves ledger entries by token ID
func (tl *TokenLedger) GetEntriesByTokenID(tokenID string) []LedgerEntry {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	var result []LedgerEntry
	for _, entry := range tl.entries {
		if entry.TokenID == tokenID {
			result = append(result, entry)
		}
	}

	return result
}

// GetEntriesByOwner retrieves ledger entries by owner
func (tl *TokenLedger) GetEntriesByOwner(owner string) []LedgerEntry {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	var result []LedgerEntry
	for _, entry := range tl.entries {
		if entry.From == owner || entry.To == owner {
			result = append(result, entry)
		}
	}

	return result
}

// TransferToken handles the transfer of a token and logs the entry in the ledger
func (tl *TokenLedger) TransferToken(tokenTracker *assets.Syn721TokenTracker, tokenID, from, to, transaction string) error {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	// Verify token exists and current owner
	token, err := tokenTracker.GetToken(tokenID)
	if err != nil {
		return fmt.Errorf("token with ID %s not found: %v", tokenID, err)
	}
	if token.Owner != from {
		return fmt.Errorf("ownership mismatch: token owner is %s, not %s", token.Owner, from)
	}

	// Perform the transfer
	err = tokenTracker.TransferOwnership(tokenID, to)
	if err != nil {
		return fmt.Errorf("failed to transfer ownership: %v", err)
	}

	// Log the ledger entry
	tl.AddEntry(tokenID, from, to, transaction)

	return nil
}
