package integration

import (
	"errors"
)

type BlockchainTransaction struct {
	TransactionID string
	From          string
	To            string
	Amount        float64
}

type BlockchainManager struct {
	Transactions map[string]*BlockchainTransaction
}

func NewBlockchainManager() *BlockchainManager {
	return &BlockchainManager{
		Transactions: make(map[string]*BlockchainTransaction),
	}
}

func (bm *BlockchainManager) CreateTransaction(txID, from, to string, amount float64) {
	bm.Transactions[txID] = &BlockchainTransaction{
		TransactionID: txID,
		From:          from,
		To:            to,
		Amount:        amount,
	}
}

func (bm *BlockchainManager) GetTransaction(txID string) (*BlockchainTransaction, error) {
	tx, exists := bm.Transactions[txID]
	if !exists {
		return nil, errors.New("transaction not found")
	}
	return tx, nil
}

func (bm *BlockchainManager) ListTransactions() []*BlockchainTransaction {
	var transactions []*BlockchainTransaction
	for _, tx := range bm.Transactions {
		transactions = append(transactions, tx)
	}
	return transactions
}
