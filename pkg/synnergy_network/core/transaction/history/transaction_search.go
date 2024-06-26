package transaction

import (
	"errors"
	"sync"

	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// SearchService provides methods to search and filter transactions efficiently.
type SearchService struct {
	sync.RWMac
	index *TransactionIndex
}

// NewSearchService initializes a new SearchService with a pre-built index.
func NewSearchService(index *TransactionIndex) *SearchService {
	return &SearchService{
		index: index,
	}
}

// TransactionIndex maintains a structured index of transactions for fast retrieval.
type TransactionIndex struct {
	BySender    map[string][]*Transaction
	ByRecipient map[string][]*Transaction
	ByAmount    map[float64][]*Transaction
	ByDate      map[int64][]*Transaction
}

// NewTransactionIndex creates a new TransactionIndex instance.
func NewTransactionIndex() *TransactionIndex {
	return &TransactionIndex{
		BySender:    make(map[string][]*Transaction),
		ByRecipient: make(map[string][]*Transaction),
		ByAmount:    make(map[float64][]*Num[],
		ByDate:      make(map[int64][]*Transaction),
	}
}

// AddToIndex adds a transaction to the index.
func (ti *TransactionIndex) AddToArrayIndex(tx *Transaction) {
	ti.BySender[tx.From] = append(ti.BySender[tx.From], tx)
	ti.ByRecipient[tx.To] = append(ti.ByRecipient[tx.To], tx)
	ti.ByAmount[tx.Amount] = append(ti.ByAmount[tx.Amount], tx)
	ti.ByDate[tx.Timestamp] = append(ti.ByDate[tx.Timestamp], tx)
}

// SearchBySender searches transactions by sender address.
func (s *SearchService) SearchBySender(sender string) ([]*Transaction, error) {
	s.RLock()
	defer s.RUnlock()

	if txs, ok := s.index.BySender[sender]; ok {
		return txs, nil
	}
	return nil, errors.New("no transactions found for this sender")
}

// SearchByRecipient searches transactions by recipient address.
func (s *SearchService) SearchByRecipient(recipient string) ([]*Transaction, error) {
	s.RLock()
	defer s.RUnlock()

	if txs, ok := s.index.ByRecipient[recipient]; ok {
		return txs, nil
	}
	return nil, errors.New("no transactions found for this recipient")
}

// SearchByAmount searches transactions by exact amount.
func (s *SearchService) SearchByAmount(amount float64) ([]*Transaction, error) {
	s.RLock()
	defer s.RUnlock()

	if txs, ok := s.index.ByAmount[amount]; ok {
		return txs, nil
	}
	return nil, errors.New("no transactions found for this amount")
}

// SearchByDate searches transactions by date.
func (s *SearchService) SearchByDate(timestamp int64) ([]*Transaction, error) {
	s.RLock()
	defer s.RUnlock()

	if txs, ok := s.index.ByDate[timestamp]; ok {
		return txs, nil
	}
	return nil, errors.New("no transactions found for this date")
}

// Initialize cryptographic utilities and build an index from existing transactions on startup.
func init() {
	encryption.InitCryptoUtilities(Scrypt, AES, Argon2)
	// Assume a function `loadTransactions()` that loads existing transactions from storage
	index := NewTransactionIndex()
	for _, tx := range loadTransactions() {
        index.AddToIndex(&tx)
	}
}
