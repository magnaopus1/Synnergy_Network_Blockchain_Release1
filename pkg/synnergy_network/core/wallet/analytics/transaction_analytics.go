package analytics

import (
	"fmt"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction/transaction_types"
	"github.com/synthron_blockchain_final/pkg/layer0/core/wallet"
)

// TransactionAnalytics handles various analytical functionalities related to transactions.
type TransactionAnalytics struct {
	wallet     *wallet.Wallet
	transactions []transaction_types.Transaction
}

// NewTransactionAnalytics creates a new instance of TransactionAnalytics.
func NewTransactionAnalytics(wallet *wallet.Wallet) *TransactionAnalytics {
	return &TransactionAnalytics{
		wallet:       wallet,
		transactions: make([]transaction_types.Transaction, 0),
	}
}

// AddTransaction adds a transaction to the analytics tracking.
func (ta *TransactionAnalytics) AddTransaction(tx transaction_types.Transaction) {
	ta.transactions = append(ta.transactions, tx)
}

// CalculateTransactionVolume calculates the total volume of transactions over a specified period.
func (ta *TransactionAnalytics) CalculateTransactionVolume(start, end time.Time) float64 {
	var totalVolume float64
	for _, tx := range ta.transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) {
			totalVolume += tx.Amount
		}
	}
	return totalVolume
}

// CalculateTransactionCount calculates the total number of transactions over a specified period.
func (ta *TransactionAnalytics) CalculateTransactionCount(start, end time.Time) int {
	count := 0
	for _, tx := range ta.transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) {
			count++
		}
	}
	return count
}

// GetLargestTransaction finds the largest transaction over a specified period.
func (ta *TransactionAnalytics) GetLargestTransaction(start, end time.Time) *transaction_types.Transaction {
	var largestTx *transaction_types.Transaction
	for _, tx := range ta.transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) {
			if largestTx == nil || tx.Amount > largestTx.Amount {
				largestTx = &tx
			}
		}
	}
	return largestTx
}

// CalculateAverageTransactionValue calculates the average value of transactions over a specified period.
func (ta *TransactionAnalytics) CalculateAverageTransactionValue(start, end time.Time) float64 {
	totalVolume := ta.CalculateTransactionVolume(start, end)
	transactionCount := ta.CalculateTransactionCount(start, end)
	if transactionCount == 0 {
		return 0
	}
	return totalVolume / float64(transactionCount)
}

// PrintTransactionReport generates and prints a report of transactions over a specified period.
func (ta *TransactionAnalytics) PrintTransactionReport(start, end time.Time) {
	fmt.Printf("Transaction Report from %s to %s:\n", start, end)
	fmt.Printf("Total Volume: %f\n", ta.CalculateTransactionVolume(start, end))
	fmt.Printf("Total Count: %d\n", ta.CalculateTransactionCount(start, end))
	largestTx := ta.GetLargestTransaction(start, end)
	if largestTx != nil {
		fmt.Printf("Largest Transaction: %f at %s\n", largestTx.Amount, largestTx.Timestamp)
	}
	fmt.Printf("Average Transaction Value: %f\n", ta.CalculateAverageTransactionValue(start, end))
}

// IdentifyAnomalies identifies transactions that deviate significantly from the average value over a specified period.
func (ta *TransactionAnalytics) IdentifyAnomalies(start, end time.Time, threshold float64) []transaction_types.Transaction {
	averageValue := ta.CalculateAverageTransactionValue(start, end)
	anomalies := make([]transaction_types.Transaction, 0)
	for _, tx := range ta.transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) {
			if tx.Amount > averageValue*threshold {
				anomalies = append(anomalies, tx)
			}
		}
	}
	return anomalies
}

// GenerateCSVReport generates a CSV report of transactions over a specified period.
func (ta *TransactionAnalytics) GenerateCSVReport(start, end time.Time) string {
	csv := "Timestamp,Amount\n"
	for _, tx := range ta.transactions {
		if tx.Timestamp.After(start) && tx.Timestamp.Before(end) {
			csv += fmt.Sprintf("%s,%f\n", tx.Timestamp, tx.Amount)
		}
	}
	return csv
}
