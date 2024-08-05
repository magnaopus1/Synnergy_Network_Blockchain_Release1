package ledger

import (
    "errors"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/synnergy_network/core/tokens/token_standards/syn223/transactions"
    "github.com/synnergy_network/security"
    "github.com/synnergy_network/utils"
)

// BalanceRecord holds the balance of tokens for each address.
type BalanceRecord struct {
    Address string
    Balance uint64
}

// Ledger stores all balances and transaction logs for tokens.
type Ledger struct {
    mu             sync.RWMutex
    balances       map[string]map[string]uint64 // map[tokenID]map[address]balance
    transactions   map[string][]transactions.Transaction
}

// NewLedger initializes a new ledger instance.
func NewLedger() *Ledger {
    return &Ledger{
        balances:     make(map[string]map[string]uint64),
        transactions: make(map[string][]transactions.Transaction),
    }
}

// GetBalance returns the balance of a specific address for a given token ID.
func (l *Ledger) GetBalance(address, tokenID string) (uint64, error) {
    l.mu.RLock()
    defer l.mu.RUnlock()

    if _, exists := l.balances[tokenID]; !exists {
        return 0, errors.New("token ID not found")
    }

    balance, exists := l.balances[tokenID][address]
    if !exists {
        return 0, nil
    }

    return balance, nil
}

// UpdateBalance updates the balance of a specific address for a given token ID.
func (l *Ledger) UpdateBalance(address, tokenID string, amount int64) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    if _, exists := l.balances[tokenID]; !exists {
        l.balances[tokenID] = make(map[string]uint64)
    }

    currentBalance := l.balances[tokenID][address]
    newBalance := int64(currentBalance) + amount
    if newBalance < 0 {
        return errors.New("insufficient balance")
    }

    l.balances[tokenID][address] = uint64(newBalance)
    return nil
}

// LogTransaction logs a transaction to the ledger.
func (l *Ledger) LogTransaction(tx transactions.Transaction) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    if _, exists := l.transactions[tx.TokenID]; !exists {
        l.transactions[tx.TokenID] = []transactions.Transaction{}
    }

    l.transactions[tx.TokenID] = append(l.transactions[tx.TokenID], tx)
    return nil
}

// GetTransactionLogs returns the transaction logs for a specific token ID.
func (l *Ledger) GetTransactionLogs(tokenID string) ([]transactions.Transaction, error) {
    l.mu.RLock()
    defer l.mu.RUnlock()

    txLogs, exists := l.transactions[tokenID]
    if !exists {
        return nil, errors.New("transaction logs not found for this token ID")
    }

    return txLogs, nil
}

// TransferTokens handles the transfer of tokens from one address to another.
func (l *Ledger) TransferTokens(from, to, tokenID string, amount uint64) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    // Verify sender's balance
    senderBalance, exists := l.balances[tokenID][from]
    if !exists || senderBalance < amount {
        return errors.New("insufficient balance")
    }

    // Update balances
    l.balances[tokenID][from] -= amount
    if _, exists := l.balances[tokenID][to]; !exists {
        l.balances[tokenID][to] = 0
    }
    l.balances[tokenID][to] += amount

    // Log the transfer transaction
    transferTx := transactions.Transaction{
        ID:        uuid.New().String(),
        TokenID:   tokenID,
        From:      from,
        To:        to,
        Amount:    amount,
        Timestamp: time.Now().Unix(),
        Metadata:  "Token transfer",
    }
    l.transactions[tokenID] = append(l.transactions[tokenID], transferTx)

    return nil
}

// SafeTransferTokens ensures that tokens are only transferred to valid addresses/contracts.
func (l *Ledger) SafeTransferTokens(from, to, tokenID string, amount uint64, isValidReceiver func(string) bool) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    // Verify sender's balance
    senderBalance, exists := l.balances[tokenID][from]
    if !exists || senderBalance < amount {
        return errors.New("insufficient balance")
    }

    // Verify receiver's validity
    if !isValidReceiver(to) {
        return errors.New("invalid receiver address")
    }

    // Update balances
    l.balances[tokenID][from] -= amount
    if _, exists := l.balances[tokenID][to]; !exists {
        l.balances[tokenID][to] = 0
    }
    l.balances[tokenID][to] += amount

    // Log the transfer transaction
    transferTx := transactions.Transaction{
        ID:        uuid.New().String(),
        TokenID:   tokenID,
        From:      from,
        To:        to,
        Amount:    amount,
        Timestamp: time.Now().Unix(),
        Metadata:  "Safe token transfer",
    }
    l.transactions[tokenID] = append(l.transactions[tokenID], transferTx)

    return nil
}
