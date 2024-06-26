package transaction_monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// ComplianceReport represents a compliance report containing transaction summaries and detected anomalies
type ComplianceReport struct {
	ReportID      string            `json:"report_id"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Transactions  []Transaction     `json:"transactions"`
	Anomalies     []Anomaly         `json:"anomalies"`
	UserActivities []UserActivity   `json:"user_activities"`
}

// ComplianceReportingSystem manages the generation and storage of compliance reports
type ComplianceReportingSystem struct {
	db       *sql.DB
	reports  chan ComplianceReport
	filePath string
}

// NewComplianceReportingSystem initializes a new compliance reporting system
func NewComplianceReportingSystem(db *sql.DB, filePath string) *ComplianceReportingSystem {
	return &ComplianceReportingSystem{
		db:       db,
		reports:  make(chan ComplianceReport, 100),
		filePath: filePath,
	}
}

// Start begins the compliance reporting process
func (crs *ComplianceReportingSystem) Start(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			crs.generateReport()
		case report := <-crs.reports:
			crs.saveReportToFile(report)
		case <-ctx.Done():
			return
		}
	}
}

// generateReport fetches the data and generates a compliance report
func (crs *ComplianceReportingSystem) generateReport() {
	transactions, err := crs.fetchTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	anomalies, err := crs.fetchAnomalies()
	if err != nil {
		log.Println("Error fetching anomalies:", err)
		return
	}

	activities, err := crs.fetchUserActivities()
	if err != nil {
		log.Println("Error fetching user activities:", err)
		return
	}

	report := ComplianceReport{
		ReportID:      generateReportID(),
		GeneratedAt:   time.Now(),
		Transactions:  transactions,
		Anomalies:     anomalies,
		UserActivities: activities,
	}

	crs.reports <- report
}

// fetchTransactions retrieves all transactions from the database
func (crs *ComplianceReportingSystem) fetchTransactions() ([]Transaction, error) {
	rows, err := crs.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions 
		WHERE timestamp > NOW() - INTERVAL '24 HOURS'`)
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

// fetchAnomalies retrieves all detected anomalies from the database
func (crs *ComplianceReportingSystem) fetchAnomalies() ([]Anomaly, error) {
	rows, err := crs.db.Query(`
		SELECT transaction_id, detected_at, reason 
		FROM anomalies 
		WHERE detected_at > NOW() - INTERVAL '24 HOURS'`)
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

// fetchUserActivities retrieves all user activities from the database
func (crs *ComplianceReportingSystem) fetchUserActivities() ([]UserActivity, error) {
	rows, err := crs.db.Query(`
		SELECT id, user_id, timestamp, activity_type, details 
		FROM user_activities 
		WHERE timestamp > NOW() - INTERVAL '24 HOURS'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activities []UserActivity
	for rows.Next() {
		var activity UserActivity
		if err := rows.Scan(&activity.ID, &activity.UserID, &activity.Timestamp, &activity.ActivityType, &activity.Details); err != nil {
			return nil, err
		}
		activities = append(activities, activity)
	}
	return activities, rows.Err()
}

// saveReportToFile saves the generated report to a file
func (crs *ComplianceReportingSystem) saveReportToFile(report ComplianceReport) {
	fileName := fmt.Sprintf("%s/report_%s.json", crs.filePath, report.ReportID)
	file, err := os.Create(fileName)
	if err != nil {
		log.Println("Error creating report file:", err)
		return
	}
	defer file.Close()

	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Println("Error marshalling report data:", err)
		return
	}

	if _, err := file.Write(reportData); err != nil {
		log.Println("Error writing report to file:", err)
	}
}

// generateReportID generates a unique ID for each compliance report
func generateReportID() string {
	return fmt.Sprintf("report_%d", time.Now().UnixNano())
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
