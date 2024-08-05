package transactions

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/assets"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
)

// Transaction represents a transaction in the SYN721 token system
type Transaction struct {
	ID        string
	Timestamp time.Time
	Sender    string
	Receiver  string
	TokenID   string
	Type      string
	Status    string
}

// TransactionManager manages transactions for SYN721 tokens
type TransactionManager struct {
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	transactions    map[string]Transaction
	mutex           sync.Mutex
}

// NewTransactionManager initializes a new TransactionManager
func NewTransactionManager(ledger *ledger.Ledger, securityManager *security.SecurityManager) *TransactionManager {
	return &TransactionManager{
		ledger:          ledger,
		securityManager: securityManager,
		transactions:    make(map[string]Transaction),
	}
}

// CreateMintTransaction creates a new mint transaction
func (tm *TransactionManager) CreateMintTransaction(sender string, metadata assets.Metadata, valuation assets.Valuation) (string, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tokenID, err := tm.ledger.GenerateTokenID()
	if err != nil {
		return "", err
	}

	token := assets.Syn721Token{
		ID:        tokenID,
		Owner:     sender,
		Metadata:  metadata,
		Valuation: valuation,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = tm.ledger.AddToken(token)
	if err != nil {
		return "", err
	}

	transactionID := fmt.Sprintf("%s_%s_%d", sender, tokenID, time.Now().UnixNano())
	transaction := Transaction{
		ID:        transactionID,
		Timestamp: time.Now(),
		Sender:    sender,
		Receiver:  sender,
		TokenID:   tokenID,
		Type:      "Mint",
		Status:    "Completed",
	}

	tm.transactions[transactionID] = transaction

	return transactionID, nil
}

// CreateTransferTransaction creates a new transfer transaction
func (tm *TransactionManager) CreateTransferTransaction(sender, receiver, tokenID string) (string, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, err := tm.ledger.GetToken(tokenID)
	if err != nil {
		return "", err
	}

	if token.Owner != sender {
		return "", errors.New("sender does not own the token")
	}

	err = tm.ledger.TransferOwnership(tokenID, receiver)
	if err != nil {
		return "", err
	}

	transactionID := fmt.Sprintf("%s_%s_%d", sender, tokenID, time.Now().UnixNano())
	transaction := Transaction{
		ID:        transactionID,
		Timestamp: time.Now(),
		Sender:    sender,
		Receiver:  receiver,
		TokenID:   tokenID,
		Type:      "Transfer",
		Status:    "Completed",
	}

	tm.transactions[transactionID] = transaction

	return transactionID, nil
}

// CreateBurnTransaction creates a new burn transaction
func (tm *TransactionManager) CreateBurnTransaction(sender, tokenID string) (string, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, err := tm.ledger.GetToken(tokenID)
	if err != nil {
		return "", err
	}

	if token.Owner != sender {
		return "", errors.New("sender does not own the token")
	}

	err = tm.ledger.RemoveToken(tokenID)
	if err != nil {
		return "", err
	}

	transactionID := fmt.Sprintf("%s_%s_%d", sender, tokenID, time.Now().UnixNano())
	transaction := Transaction{
		ID:        transactionID,
		Timestamp: time.Now(),
		Sender:    sender,
		Receiver:  "",
		TokenID:   tokenID,
		Type:      "Burn",
		Status:    "Completed",
	}

	tm.transactions[transactionID] = transaction

	return transactionID, nil
}

// GetTransaction retrieves a transaction by its ID
func (tm *TransactionManager) GetTransaction(transactionID string) (Transaction, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	transaction, exists := tm.transactions[transactionID]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}

	return transaction, nil
}

// GetTransactionsByToken retrieves all transactions related to a specific token ID
func (tm *TransactionManager) GetTransactionsByToken(tokenID string) ([]Transaction, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var transactions []Transaction
	for _, transaction := range tm.transactions {
		if transaction.TokenID == tokenID {
			transactions = append(transactions, transaction)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the token ID")
	}

	return transactions, nil
}

// GetTransactionsBySender retrieves all transactions initiated by a specific sender
func (tm *TransactionManager) GetTransactionsBySender(sender string) ([]Transaction, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var transactions []Transaction
	for _, transaction := range tm.transactions {
		if transaction.Sender == sender {
			transactions = append(transactions, transaction)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the sender")
	}

	return transactions, nil
}

// GetTransactionsByReceiver retrieves all transactions received by a specific receiver
func (tm *TransactionManager) GetTransactionsByReceiver(receiver string) ([]Transaction, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	var transactions []Transaction
	for _, transaction := range tm.transactions {
		if transaction.Receiver == receiver {
			transactions = append(transactions, transaction)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the receiver")
	}

	return transactions, nil
}
