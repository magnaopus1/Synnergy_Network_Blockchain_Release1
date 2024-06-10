package syn1800

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// CarbonToken represents a unit of carbon footprint, with properties for detailed tracking.
type CarbonToken struct {
	TokenID     string    `json:"tokenId"`
	Owner       string    `json:"owner"`
	Amount      float64   `json:"amount"` // Negative for emissions, positive for offsets
	IssuedDate  time.Time `json:"issuedDate"`
	Description string    `json:"description"` // Detailed description of emission or offset activity
	Source      string    `json:"source"`      // Source of the emission data or offset verification
}

// CarbonAccount aggregates all tokens to provide a net balance and historical data.
type CarbonAccount struct {
	Owner       string        `json:"owner"`
	Balance     float64       `json:"balance"` // Net carbon footprint (negative indicates debt)
	Tokens      []CarbonToken `json:"tokens"`
	LastUpdated time.Time     `json:"lastUpdated"`
	mutex       sync.Mutex    // Protects access to the CarbonAccount
}

// SYN1800Ledger provides a comprehensive management system for carbon tokens.
type SYN1800Ledger struct {
	Accounts map[string]*CarbonAccount
	mutex    sync.Mutex // Ensures thread-safe access to the Accounts map
}

// NewSYN1800Ledger initializes a ledger with concurrent-safe properties.
func NewSYN1800Ledger() *SYN1800Ledger {
	return &SYN1800Ledger{
		Accounts: make(map[string]*CarbonAccount),
	}
}

// IssueToken safely issues new carbon tokens, adjusting the recipient's balance.
func (l *SYN1800Ledger) IssueToken(owner string, amount float64, tokenID, description, source string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	account, exists := l.Accounts[owner]
	if !exists {
		account = &CarbonAccount{
			Owner:   owner,
			Balance: 0,
			Tokens:  []CarbonToken{},
		}
		l.Accounts[owner] = account
	}

	account.mutex.Lock()
	defer account.mutex.Unlock()

	token := CarbonToken{
		TokenID:     tokenID,
		Owner:       owner,
		Amount:      amount,
		IssuedDate:  time.Now(),
		Description: description,
		Source:      source,
	}

	account.Tokens = append(account.Tokens, token)
	account.Balance += amount
	account.LastUpdated = time.Now()

	return nil
}

// TransferToken facilitates the secure transfer of tokens between accounts.
func (l *SYN1800Ledger) TransferToken(from, to, tokenID string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	fromAccount, exists := l.Accounts[from]
	if !exists {
		return errors.New("source account does not exist")
	}

	fromAccount.mutex.Lock()
	defer fromAccount.mutex.Unlock()

	toAccount, exists := l.Accounts[to]
	if !exists {
		toAccount = &CarbonAccount{
			Owner:   to,
			Balance: 0,
			Tokens:  []CarbonToken{},
		}
		l.Accounts[to] = toAccount
	}

	toAccount.mutex.Lock()
	defer toAccount.mutex.Unlock()

	index := -1
	for i, token := range fromAccount.Tokens {
		if token.TokenID == tokenID {
			index = i
			break
		}
	}

	if index == -1 {
		return fmt.Errorf("token %s not found in account %s", tokenID, from)
	}

	token := fromAccount.Tokens[index]
	fromAccount.Tokens = append(fromAccount.Tokens[:index], fromAccount.Tokens[index+1:]...)
	fromAccount.Balance -= token.Amount

	// Transfer the token
	token.Owner = to
	toAccount.Tokens = append(toAccount.Tokens, token)
	toAccount.Balance += token.Amount

	return nil
}

// GetAccountInfo retrieves the details of a specific carbon account, including transaction history.
func (l *SYN1800Ledger) GetAccountInfo(owner string) (*CarbonAccount, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	account, exists := l.Accounts[owner]
	if !exists {
		return nil, fmt.Errorf("account %s does not exist", owner)
	}
	return account, nil
}
