package transactions

import (
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

// ForexTransaction represents a single Forex transaction
type ForexTransaction struct {
	TransactionID string
	PairID        string
	Buyer         common.Address
	Seller        common.Address
	Price         *big.Int
	Amount        *big.Int
	Timestamp     time.Time
}

// ForexTransactionHistory manages the history of Forex transactions
type ForexTransactionHistory struct {
	client            *rpc.Client
	transactions      []ForexTransaction
	mutex             sync.Mutex
	ledgerManager     *ledger.LedgerManager
	transactionChan   chan ForexTransaction
}

// NewForexTransactionHistory initializes a new ForexTransactionHistory instance
func NewForexTransactionHistory(clientURL string, ledgerMgr *ledger.LedgerManager) (*ForexTransactionHistory, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	return &ForexTransactionHistory{
		client:          client,
		transactions:    []ForexTransaction{},
		ledgerManager:   ledgerMgr,
		transactionChan: make(chan ForexTransaction, 100),
	}, nil
}

// StartProcessing starts processing Forex transactions
func (fth *ForexTransactionHistory) StartProcessing() {
	go func() {
		for tx := range fth.transactionChan {
			fth.mutex.Lock()
			fth.transactions = append(fth.transactions, tx)
			fth.mutex.Unlock()
			fth.recordTransaction(tx)
		}
	}()
}

// AddTransaction adds a new Forex transaction to the history
func (fth *ForexTransactionHistory) AddTransaction(pairID string, buyer, seller common.Address, price, amount *big.Int) error {
	tx := ForexTransaction{
		TransactionID: generateTransactionID(),
		PairID:        pairID,
		Buyer:         buyer,
		Seller:        seller,
		Price:         price,
		Amount:        amount,
		Timestamp:     time.Now(),
	}
	fth.transactionChan <- tx
	return nil
}

// GetTransactionByID retrieves a Forex transaction by its ID
func (fth *ForexTransactionHistory) GetTransactionByID(transactionID string) (*ForexTransaction, error) {
	fth.mutex.Lock()
	defer fth.mutex.Unlock()

	for _, tx := range fth.transactions {
		if tx.TransactionID == transactionID {
			return &tx, nil
		}
	}
	return nil, errors.New("transaction not found")
}

// GetTransactionsByAddress retrieves Forex transactions by an address
func (fth *ForexTransactionHistory) GetTransactionsByAddress(address common.Address) ([]ForexTransaction, error) {
	fth.mutex.Lock()
	defer fth.mutex.Unlock()

	var result []ForexTransaction
	for _, tx := range fth.transactions {
		if tx.Buyer == address || tx.Seller == address {
			result = append(result, tx)
		}
	}
	return result, nil
}

// GetTransactionsByPairID retrieves Forex transactions by pair ID
func (fth *ForexTransactionHistory) GetTransactionsByPairID(pairID string) ([]ForexTransaction, error) {
	fth.mutex.Lock()
	defer fth.mutex.Unlock()

	var result []ForexTransaction
	for _, tx := range fth.transactions {
		if tx.PairID == pairID {
			result = append(result, tx)
		}
	}
	return result, nil
}

// GetTransactionHistory retrieves the complete history of Forex transactions
func (fth *ForexTransactionHistory) GetTransactionHistory() ([]ForexTransaction, error) {
	fth.mutex.Lock()
	defer fth.mutex.Unlock()

	return fth.transactions, nil
}

// recordTransaction records a transaction in the ledger
func (fth *ForexTransactionHistory) recordTransaction(tx ForexTransaction) {
	ledgerTx := ledger.Transaction{
		TransactionID: tx.TransactionID,
		From:          tx.Buyer,
		To:            tx.Seller,
		Value:         tx.Price,
		Data:          nil,
		Timestamp:     tx.Timestamp,
	}

	err := fth.ledgerManager.RecordTransaction(&ledgerTx)
	if err != nil {
		log.Printf("Failed to record transaction in ledger: %v", err)
	}
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return common.Bytes2Hex([]byte(time.Now().String() + time.Now().UTC().String()))
}
