package fraud_detection

import (
	"errors"
	"log"
	"math"
	"math/rand"
	"time"
)

// AnomalyDetection is a struct that handles the detection of fraudulent transactions in the blockchain.
type AnomalyDetection struct {
	threshold    float64
	alertChannel chan string
}

// NewAnomalyDetection creates a new instance of AnomalyDetection.
func NewAnomalyDetection(threshold float64) *AnomalyDetection {
	return &AnomalyDetection{
		threshold:    threshold,
		alertChannel: make(chan string),
	}
}

// DetectAnomalies checks the transactions for any anomalies based on the threshold.
func (ad *AnomalyDetection) DetectAnomalies(transactions []Transaction) ([]Transaction, error) {
	if len(transactions) == 0 {
		return nil, errors.New("no transactions provided")
	}

	var anomalies []Transaction
	for _, tx := range transactions {
		if ad.isAnomalous(tx) {
			anomalies = append(anomalies, tx)
			ad.alertChannel <- tx.ID
		}
	}
	return anomalies, nil
}

// isAnomalous determines if a transaction is anomalous based on the threshold.
func (ad *AnomalyDetection) isAnomalous(tx Transaction) bool {
	return math.Abs(tx.Amount) > ad.threshold
}

// MonitorAlerts monitors the alert channel for anomalous transactions.
func (ad *AnomalyDetection) MonitorAlerts() {
	for {
		select {
		case txID := <-ad.alertChannel:
			ad.handleAlert(txID)
		}
	}
}

// handleAlert handles an alert for an anomalous transaction.
func (ad *AnomalyDetection) handleAlert(txID string) {
	log.Printf("Alert: Anomalous transaction detected with ID: %s\n", txID)
}

// Transaction represents a transaction in the blockchain.
type Transaction struct {
	ID          string
	Sender      string
	Receiver    string
	Amount      float64
	Description string
	Timestamp   time.Time
}

// TransactionGenerator generates random transactions for testing.
type TransactionGenerator struct{}

// NewTransactionGenerator creates a new instance of TransactionGenerator.
func NewTransactionGenerator() *TransactionGenerator {
	return &TransactionGenerator{}
}

// GenerateRandomTransactions generates a list of random transactions.
func (tg *TransactionGenerator) GenerateRandomTransactions(count int) []Transaction {
	var transactions []Transaction
	for i := 0; i < count; i++ {
		transactions = append(transactions, Transaction{
			ID:          generateRandomString(10),
			Sender:      generateRandomString(5),
			Receiver:    generateRandomString(5),
			Amount:      rand.Float64() * 10000,
			Description: generateRandomString(20),
			Timestamp:   time.Now(),
		})
	}
	return transactions
}

// generateRandomString generates a random string of the given length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// Blockchain represents the entire chain of transactions.
type Blockchain struct {
	transactions []Transaction
	detector     *AnomalyDetection
}

// NewBlockchain initializes a new blockchain with anomaly detection.
func NewBlockchain(threshold float64) *Blockchain {
	detector := NewAnomalyDetection(threshold)
	return &Blockchain{
		transactions: []Transaction{},
		detector:     detector,
	}
}

// AddTransaction adds a new transaction to the blockchain.
func (bc *Blockchain) AddTransaction(tx Transaction) error {
	bc.transactions = append(bc.transactions, tx)
	anomalies, err := bc.detector.DetectAnomalies([]Transaction{tx})
	if err != nil {
		return err
	}
	if len(anomalies) > 0 {
		bc.detector.handleAlert(tx.ID)
	}
	return nil
}

// GetTransactions returns all transactions in the blockchain.
func (bc *Blockchain) GetTransactions() []Transaction {
	return bc.transactions
}

// StartMonitoring starts the monitoring of anomalous transactions.
func (bc *Blockchain) StartMonitoring() {
	go bc.detector.MonitorAlerts()
}

// main function for testing
/*
func main() {
	threshold := 5000.0
	bc := NewBlockchain(threshold)
	bc.StartMonitoring()

	tg := NewTransactionGenerator()
	transactions := tg.GenerateRandomTransactions(10)

	for _, tx := range transactions {
		err := bc.AddTransaction(tx)
		if err != nil {
			log.Fatalf("Error adding transaction: %v", err)
		}
	}

	for _, tx := range bc.GetTransactions() {
		log.Printf("Transaction: %+v\n", tx)
	}
}
*/
