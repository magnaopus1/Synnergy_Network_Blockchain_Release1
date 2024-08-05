package trading

import (
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

// Transaction represents a single transaction in the transaction history
type Transaction struct {
	TransactionID string
	Buyer         common.Address
	Seller        common.Address
	Price         *big.Int
	Amount        *big.Int
	Timestamp     time.Time
}

// TransactionHistory manages the transaction history for Forex trades
type TransactionHistory struct {
	client           *rpc.Client
	transactions     []Transaction
	mutex            sync.Mutex
	ledgerManager    *ledger.LedgerManager
	transactionMgr   *transactions.TransactionManager
	historyChan      chan Transaction
}

// NewTransactionHistory initializes a new TransactionHistory instance
func NewTransactionHistory(clientURL string, ledgerMgr *ledger.LedgerManager, txMgr *transactions.TransactionManager) (*TransactionHistory, error) {
	client, err := rpc.Dial(clientURL)
	if err != nil {
		return nil, err
	}

	return &TransactionHistory{
		client:         client,
		transactions:   []Transaction{},
		ledgerManager:  ledgerMgr,
		transactionMgr: txMgr,
		historyChan:    make(chan Transaction, 100),
	}, nil
}

// StartTransactionHistoryProcessing starts the transaction history processing
func (th *TransactionHistory) StartTransactionHistoryProcessing() {
	go func() {
		for tx := range th.historyChan {
			th.mutex.Lock()
			th.transactions = append(th.transactions, tx)
			th.mutex.Unlock()
			th.recordTransaction(tx)
		}
	}()
}

// AddTransaction adds a new transaction to the history
func (th *TransactionHistory) AddTransaction(buyer, seller common.Address, price, amount *big.Int) error {
	tx := Transaction{
		TransactionID: generateTransactionID(),
		Buyer:         buyer,
		Seller:        seller,
		Price:         price,
		Amount:        amount,
		Timestamp:     time.Now(),
	}
	th.historyChan <- tx
	return nil
}

// GetTransactionByID retrieves a transaction by its ID
func (th *TransactionHistory) GetTransactionByID(transactionID string) (*Transaction, error) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	for _, tx := range th.transactions {
		if tx.TransactionID == transactionID {
			return &tx, nil
		}
	}
	return nil, errors.New("transaction not found")
}

// GetTransactionsByAddress retrieves transactions by an address
func (th *TransactionHistory) GetTransactionsByAddress(address common.Address) ([]Transaction, error) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	var result []Transaction
	for _, tx := range th.transactions {
		if tx.Buyer == address || tx.Seller == address {
			result = append(result, tx)
		}
	}
	return result, nil
}

// GetTransactionHistory retrieves the complete transaction history
func (th *TransactionHistory) GetTransactionHistory() ([]Transaction, error) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	return th.transactions, nil
}

// recordTransaction records a transaction in the ledger
func (th *TransactionHistory) recordTransaction(tx Transaction) {
	ledgerTx := transactions.Transaction{
		TransactionID: tx.TransactionID,
		From:          tx.Buyer,
		To:            tx.Seller,
		Value:         tx.Price,
		Gas:           big.NewInt(0), // Assume zero gas for simplicity
		Data:          nil,
	}

	err := th.ledgerManager.RecordTransaction(&ledgerTx)
	if err != nil {
		log.Printf("Failed to record transaction in ledger: %v", err)
	}
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return common.Bytes2Hex([]byte(time.Now().String()))
}
