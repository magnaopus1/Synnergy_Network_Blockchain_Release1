package transaction_monitoring

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
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

// RealTimeAlert represents a real-time alert
type RealTimeAlert struct {
	AlertID       string    `json:"alert_id"`
	TransactionID string    `json:"transaction_id"`
	AlertType     string    `json:"alert_type"`
	Message       string    `json:"message"`
	Timestamp     time.Time `json:"timestamp"`
}

// RealTimeAlertSystem manages real-time alerts
type RealTimeAlertSystem struct {
	db       *sql.DB
	natsConn *nats.Conn
}

// NewRealTimeAlertSystem initializes a new real-time alert system
func NewRealTimeAlertSystem(db *sql.DB, natsURL string) (*RealTimeAlertSystem, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}
	return &RealTimeAlertSystem{
		db:       db,
		natsConn: nc,
	}, nil
}

// Start begins the real-time alert monitoring process
func (rtas *RealTimeAlertSystem) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rtas.checkForSuspiciousActivities()
		case <-ctx.Done():
			rtas.natsConn.Close()
			return
		}
	}
}

// checkForSuspiciousActivities fetches recent transactions and checks for suspicious activities
func (rtas *RealTimeAlertSystem) checkForSuspiciousActivities() {
	transactions, err := rtas.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	for _, tx := range transactions {
		if rtas.isSuspicious(tx) {
			alert := RealTimeAlert{
				AlertID:       generateAlertID(),
				TransactionID: tx.ID,
				AlertType:     "Suspicious Transaction",
				Message:       fmt.Sprintf("Suspicious activity detected for transaction %s", tx.ID),
				Timestamp:     time.Now(),
			}
			rtas.handleAlert(alert)
		}
	}
}

// fetchRecentTransactions retrieves recent transactions from the database
func (rtas *RealTimeAlertSystem) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := rtas.db.Query(`
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

// isSuspicious determines if a transaction is suspicious based on predefined criteria
func (rtas *RealTimeAlertSystem) isSuspicious(tx Transaction) bool {
	// Example criteria for detecting suspicious activity (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}

// handleAlert processes a detected alert
func (rtas *RealTimeAlertSystem) handleAlert(alert RealTimeAlert) {
	// Log the alert
	log.Printf("Alert detected: %+v\n", alert)

	// Publish the alert to the messaging system (e.g., NATS)
	if err := rtas.publishAlert(alert); err != nil {
		log.Println("Error publishing alert:", err)
	}

	// Save the alert to the database
	if err := rtas.saveAlertToDB(alert); err != nil {
		log.Println("Error saving alert to database:", err)
	}
}

// publishAlert publishes an alert to the messaging system
func (rtas *RealTimeAlertSystem) publishAlert(alert RealTimeAlert) error {
	alertData, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	return rtas.natsConn.Publish("alerts", alertData)
}

// saveAlertToDB saves an alert to the database
func (rtas *RealTimeAlertSystem) saveAlertToDB(alert RealTimeAlert) error {
	_, err := rtas.db.Exec(`
		INSERT INTO alerts (alert_id, transaction_id, alert_type, message, timestamp) 
		VALUES ($1, $2, $3, $4, $5)`,
		alert.AlertID, alert.TransactionID, alert.AlertType, alert.Message, alert.Timestamp)
	return err
}

// generateAlertID generates a unique ID for each alert
func generateAlertID() string {
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
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
