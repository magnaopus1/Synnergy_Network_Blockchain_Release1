package transactions

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
)

// SaleRecord represents a sale transaction of a SYN721 token
type SaleRecord struct {
	Timestamp   time.Time
	TokenID     string
	Seller      string
	Buyer       string
	Price       float64
	Transaction string // Transaction ID
}

// SaleHistoryManager manages the sale history of SYN721 tokens
type SaleHistoryManager struct {
	saleHistoryStore map[string][]SaleRecord
	ledger           *ledger.Ledger
	mutex            sync.Mutex
}

// NewSaleHistoryManager initializes a new SaleHistoryManager
func NewSaleHistoryManager(ledger *ledger.Ledger) *SaleHistoryManager {
	return &SaleHistoryManager{
		saleHistoryStore: make(map[string][]SaleRecord),
		ledger:           ledger,
	}
}

// RecordSale records a new sale of a SYN721 token
func (shm *SaleHistoryManager) RecordSale(tokenID, seller, buyer string, price float64, transactionID string) error {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	// Verify token existence and ownership
	token, err := shm.ledger.GetToken(tokenID)
	if err != nil {
		return fmt.Errorf("token not found: %v", err)
	}

	if token.Owner != seller {
		return fmt.Errorf("seller is not the current owner of the token")
	}

	// Update the token's ownership
	err = shm.ledger.TransferOwnership(tokenID, buyer)
	if err != nil {
		return fmt.Errorf("failed to transfer token ownership: %v", err)
	}

	// Record the sale
	saleRecord := SaleRecord{
		Timestamp:   time.Now(),
		TokenID:     tokenID,
		Seller:      seller,
		Buyer:       buyer,
		Price:       price,
		Transaction: transactionID,
	}

	shm.saleHistoryStore[tokenID] = append(shm.saleHistoryStore[tokenID], saleRecord)
	return nil
}

// GetSaleHistory retrieves the sale history of a SYN721 token by its ID
func (shm *SaleHistoryManager) GetSaleHistory(tokenID string) ([]SaleRecord, error) {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	history, exists := shm.saleHistoryStore[tokenID]
	if !exists {
		return nil, fmt.Errorf("no sale history found for token ID %s", tokenID)
	}

	return history, nil
}

// GetRecentSales retrieves recent sales across all SYN721 tokens
func (shm *SaleHistoryManager) GetRecentSales(limit int) ([]SaleRecord, error) {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	var recentSales []SaleRecord
	for _, records := range shm.saleHistoryStore {
		recentSales = append(recentSales, records...)
	}

	if len(recentSales) > limit {
		recentSales = recentSales[len(recentSales)-limit:]
	}

	return recentSales, nil
}

// GetTotalSalesValue calculates the total sales value for a specific token
func (shm *SaleHistoryManager) GetTotalSalesValue(tokenID string) (float64, error) {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	history, exists := shm.saleHistoryStore[tokenID]
	if !exists {
		return 0, fmt.Errorf("no sale history found for token ID %s", tokenID)
	}

	var totalSalesValue float64
	for _, record := range history {
		totalSalesValue += record.Price
	}

	return totalSalesValue, nil
}

// GetTotalSalesValueAllTokens calculates the total sales value for all tokens
func (shm *SaleHistoryManager) GetTotalSalesValueAllTokens() (float64, error) {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()

	var totalSalesValue float64
	for _, records := range shm.saleHistoryStore {
		for _, record := range records {
			totalSalesValue += record.Price
		}
	}

	return totalSalesValue, nil
}
