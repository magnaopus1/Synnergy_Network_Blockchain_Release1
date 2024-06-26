package transaction_monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

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
	Category  string    `json:"category"`
}

// Anomaly represents a detected anomaly in transactions
type Anomaly struct {
	TransactionID string    `json:"transaction_id"`
	DetectedAt    time.Time `json:"detected_at"`
	Reason        string    `json:"reason"`
}

// DashboardData represents the data to be displayed on the transaction monitoring dashboard
type DashboardData struct {
	TotalTransactions int           `json:"total_transactions"`
	Anomalies         []Anomaly     `json:"anomalies"`
	RecentTransactions []Transaction `json:"recent_transactions"`
}

// TransactionDashboard manages the transaction monitoring dashboard
type TransactionDashboard struct {
	db       *sql.DB
	data     DashboardData
	dataLock sync.Mutex
}

// NewTransactionDashboard initializes a new transaction dashboard
func NewTransactionDashboard(db *sql.DB) *TransactionDashboard {
	return &TransactionDashboard{
		db: db,
	}
}

// Start begins the transaction dashboard data update process
func (td *TransactionDashboard) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			td.updateDashboardData()
		case <-ctx.Done():
			return
		}
	}
}

// updateDashboardData updates the data displayed on the dashboard
func (td *TransactionDashboard) updateDashboardData() {
	td.dataLock.Lock()
	defer td.dataLock.Unlock()

	totalTransactions, err := td.getTotalTransactions()
	if err != nil {
		log.Println("Error getting total transactions:", err)
		return
	}

	anomalies, err := td.getRecentAnomalies()
	if err != nil {
		log.Println("Error getting recent anomalies:", err)
		return
	}

	recentTransactions, err := td.getRecentTransactions()
	if err != nil {
		log.Println("Error getting recent transactions:", err)
		return
	}

	td.data = DashboardData{
		TotalTransactions: totalTransactions,
		Anomalies:         anomalies,
		RecentTransactions: recentTransactions,
	}
}

// getTotalTransactions retrieves the total number of transactions from the database
func (td *TransactionDashboard) getTotalTransactions() (int, error) {
	var total int
	err := td.db.QueryRow(`
		SELECT COUNT(*) 
		FROM transactions`).Scan(&total)
	return total, err
}

// getRecentAnomalies retrieves recent anomalies from the database
func (td *TransactionDashboard) getRecentAnomalies() ([]Anomaly, error) {
	rows, err := td.db.Query(`
		SELECT transaction_id, detected_at, reason 
		FROM anomalies 
		WHERE detected_at > NOW() - INTERVAL '1 DAY'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []Anomaly
	for rows.Next() {
		var an Anomaly
		if err := rows.Scan(&an.TransactionID, &an.DetectedAt, &an.Reason); err != nil {
			return nil, err
		}
		anomalies = append(anomalies, an)
	}
	return anomalies, rows.Err()
}

// getRecentTransactions retrieves recent transactions from the database
func (td *TransactionDashboard) getRecentTransactions() ([]Transaction, error) {
	rows, err := td.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status, category 
		FROM transactions 
		WHERE timestamp > NOW() - INTERVAL '1 DAY'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Timestamp, &tx.Amount, &tx.Type, &tx.Status, &tx.Category); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// ServeDashboard serves the dashboard data via an HTTP endpoint
func (td *TransactionDashboard) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	td.dataLock.Lock()
	defer td.dataLock.Unlock()

	data, err := json.Marshal(td.data)
	if err != nil {
		http.Error(w, "Error marshalling dashboard data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// Utility functions for secure communication, encryption, and decryption
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func encrypt(data, passphrase []byte) ([]byte, error) {
	// Use AES for encryption
	block, err := aes.NewCipher(hashPassword(string(passphrase), nil))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(encryptedData, passphrase []byte) ([]byte, error) {
	// Use AES for decryption
	block, err := aes.NewCipher(hashPassword(string(passphrase), nil))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Ensure secure communication between services
func secureCommunication() {
	// Implement secure communication logic here
}
