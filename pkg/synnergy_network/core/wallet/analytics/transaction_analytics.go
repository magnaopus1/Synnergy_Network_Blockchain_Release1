package analytics

import (
	"encoding/json"
	"sync"
	"time"
)

// Transaction represents the basic structure of a blockchain transaction.
type Transaction struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Amount    float64   `json:"amount"`
	Fee       float64   `json:"fee"`
	Timestamp time.Time `json:"timestamp"`
}

// TransactionAnalyticsService provides methods to analyze transaction data.
type TransactionAnalyticsService struct {
	Transactions []Transaction
	mu           sync.Mutex
}

// NewTransactionAnalyticsService initializes a new instance of TransactionAnalyticsService.
func NewTransactionAnalyticsService() *TransactionAnalyticsService {
	return &TransactionAnalyticsService{
		Transactions: make([]Transaction, 0),
	}
}

// AddTransaction adds a new transaction to the analytics pool.
func (tas *TransactionAnalyticsService) AddTransaction(tx Transaction) {
	tas.mu.Lock()
	defer tas.mu.Unlock()
	tas.Transactions = append(tas.Transactions, tx)
}

// TransactionVolume calculates the total transaction volume within a specified time range.
func (tas *TransactionAnalyticsService) TransactionVolume(startTime, endTime time.Time) float64 {
	tas.mu.Lock()
	defer tas.mu.Unlock()
	var volume float64
	for _, tx := range tas.Transactions {
		if tx.Timestamp.After(startTime) && tx.Timestamp.Before(endTime) {
			volume += tx.Amount
		}
	}
	return volume
}

// AverageTransactionFee calculates the average transaction fee within a specified time range.
func (tas *TransactionAnalyticsService) AverageTransactionFee(startTime, endTime time.Time) float64 {
	tas.mu.Lock()
	defer tas.mu.Unlock()
	var totalFee float64
	var count float64
	for _, tx := range tas.Transactions {
		if tx.Timestamp.After(startTime) && tx.Timestamp.Before(endTime) {
			totalFee += tx.Fee
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return totalFee / count
}

// DetectAnomalies searches for transactions that deviate from typical patterns.
func (tas *TransactionAnalyticsService) DetectAnomalies() []Transaction {
	tas.mu.Lock()
	defer tas.mu.Unlock()
	var anomalies []Transaction
	// Example: Detect transactions with fees significantly higher than the average
	averageFee := tas.AverageTransactionFee(time.Now().AddDate(0, -1, 0), time.Now())
	for _, tx := range tas.Transactions {
		if tx.Fee > averageFee*1.5 {
			anomalies = append(anomalies, tx)
		}
	}
	return anomalies
}

// SerializeTransactions converts the transactions data to JSON.
func (tas *TransactionAnalyticsService) SerializeTransactions() ([]byte, error) {
	tas.mu.Lock()
	defer tas.mu.Unlock()
	return json.Marshal(tas.Transactions)
}
