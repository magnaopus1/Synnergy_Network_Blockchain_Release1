package transaction_monitoring

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/sajari/regression"
	_ "github.com/lib/pq"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Timestamp time.Time `json:"timestamp"`
	Amount    float64   `json:"amount"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
}

// Anomaly represents a detected anomaly in transactions
type Anomaly struct {
	TransactionID string    `json:"transaction_id"`
	DetectedAt    time.Time `json:"detected_at"`
	Reason        string    `json:"reason"`
}

// PredictiveMonitoringSystem manages predictive transaction monitoring
type PredictiveMonitoringSystem struct {
	db       *sql.DB
	model    *regression.Regression
	filePath string
}

// NewPredictiveMonitoringSystem initializes a new predictive monitoring system
func NewPredictiveMonitoringSystem(db *sql.DB, filePath string) *PredictiveMonitoringSystem {
	model := new(regression.Regression)
	model.SetObserved("Anomalous")
	model.SetVar(0, "Amount")

	return &PredictiveMonitoringSystem{
		db:       db,
		model:    model,
		filePath: filePath,
	}
}

// Start begins the predictive monitoring process
func (pms *PredictiveMonitoringSystem) Start(ctx context.Context) {
	pms.trainModel()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pms.predictAnomalies()
		case <-ctx.Done():
			return
		}
	}
}

// trainModel trains the machine learning model with historical data
func (pms *PredictiveMonitoringSystem) trainModel() {
	transactions, err := pms.fetchHistoricalTransactions()
	if err != nil {
		log.Println("Error fetching historical transactions:", err)
		return
	}

	for _, tx := range transactions {
		var isAnomalous float64
		if pms.isAnomalous(tx) {
			isAnomalous = 1
		} else {
			isAnomalous = 0
		}
		pms.model.Train(regression.DataPoint(isAnomalous, []float64{tx.Amount}))
	}

	pms.model.Run()
}

// predictAnomalies fetches recent transactions and predicts anomalies
func (pms *PredictiveMonitoringSystem) predictAnomalies() {
	transactions, err := pms.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	for _, tx := range transactions {
		anomalyScore, err := pms.model.Predict([]float64{tx.Amount})
		if err != nil {
			log.Println("Error predicting anomaly:", err)
			continue
		}
		if anomalyScore > 0.5 { // Threshold for detecting anomalies
			anomaly := Anomaly{
				TransactionID: tx.ID,
				DetectedAt:    time.Now(),
				Reason:        "Predicted anomalous transaction",
			}
			pms.handleAnomaly(anomaly)
		}
	}
}

// fetchHistoricalTransactions retrieves historical transactions from the database
func (pms *PredictiveMonitoringSystem) fetchHistoricalTransactions() ([]Transaction, error) {
	rows, err := pms.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions 
		WHERE timestamp > NOW() - INTERVAL '30 DAYS'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Timestamp, &tx.Amount, &tx.Type, &tx.Status); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// fetchRecentTransactions retrieves recent transactions from the database
func (pms *PredictiveMonitoringSystem) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := pms.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions 
		WHERE timestamp > NOW() - INTERVAL '1 MINUTE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Timestamp, &tx.Amount, &tx.Type, &tx.Status); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// isAnomalous determines if a transaction is anomalous based on predefined criteria
func (pms *PredictiveMonitoringSystem) isAnomalous(tx Transaction) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}

// handleAnomaly processes a detected anomaly
func (pms *PredictiveMonitoringSystem) handleAnomaly(anomaly Anomaly) {
	log.Printf("Anomaly detected: %+v\n", anomaly)
	// Extend this function to log, notify, and take action on anomalies
}

// saveModel saves the trained model to a file
func (pms *PredictiveMonitoringSystem) saveModel() error {
	file, err := os.Create(filepath.Join(pms.filePath, "model.csv"))
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write model coefficients
	for _, coeff := range pms.model.Coeff {
		if err := writer.Write([]string{fmt.Sprintf("%f", coeff)}); err != nil {
			return err
		}
	}
	return nil
}

// loadModel loads the trained model from a file
func (pms *PredictiveMonitoringSystem) loadModel() error {
	file, err := os.Open(filepath.Join(pms.filePath, "model.csv"))
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		var coeff float64
		if _, err := fmt.Sscanf(record[0], "%f", &coeff); err != nil {
			return err
		}
		if i < len(pms.model.Coeff) {
			pms.model.Coeff[i] = coeff
		} else {
			pms.model.Coeff = append(pms.model.Coeff, coeff)
		}
	}
	return nil
}
