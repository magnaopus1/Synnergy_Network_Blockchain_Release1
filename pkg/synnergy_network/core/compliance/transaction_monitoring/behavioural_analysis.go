package transaction_monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/argon2"
)

// UserActivity represents a user's interaction with the blockchain
type UserActivity struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Timestamp    time.Time `json:"timestamp"`
	ActivityType string    `json:"activity_type"`
	Details      string    `json:"details"`
}

// BehavioralAnalysisSystem manages the analysis of user behavior
type BehavioralAnalysisSystem struct {
	db              *sql.DB
	anomalyHandlers []func(UserActivity)
}

// NewBehavioralAnalysisSystem initializes a new behavioral analysis system
func NewBehavioralAnalysisSystem(db *sql.DB) *BehavioralAnalysisSystem {
	return &BehavioralAnalysisSystem{
		db: db,
		anomalyHandlers: []func(UserActivity){
			logAnomalousBehavior,
			notifySecurityTeam,
			restrictAccount,
		},
	}
}

// MonitorUserActivities starts the user activity monitoring process
func (bas *BehavioralAnalysisSystem) MonitorUserActivities(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bas.checkForAnomalousBehavior()
		case <-ctx.Done():
			return
		}
	}
}

// checkForAnomalousBehavior fetches recent user activities and checks for anomalies
func (bas *BehavioralAnalysisSystem) checkForAnomalousBehavior() {
	activities, err := bas.fetchRecentUserActivities()
	if err != nil {
		log.Println("Error fetching user activities:", err)
		return
	}

	for _, activity := range activities {
		if bas.isAnomalous(activity) {
			bas.handleAnomalousBehavior(activity)
		}
	}
}

// fetchRecentUserActivities retrieves recent user activities from the database
func (bas *BehavioralAnalysisSystem) fetchRecentUserActivities() ([]UserActivity, error) {
	rows, err := bas.db.Query(`
		SELECT id, user_id, timestamp, activity_type, details 
		FROM user_activities 
		WHERE timestamp > NOW() - INTERVAL '1 MINUTE'`)
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

// isAnomalous determines if a user activity is anomalous based on predefined criteria
func (bas *BehavioralAnalysisSystem) isAnomalous(activity UserActivity) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if activity.ActivityType == "unusual_login" {
		return true
	}
	if activity.ActivityType == "large_transfer" && activity.Details == "out_of_normal_hours" {
		return true
	}
	// Add more rules here (e.g., frequency of activities, unusual patterns, etc.)
	return false
}

// handleAnomalousBehavior processes a detected anomalous user activity
func (bas *BehavioralAnalysisSystem) handleAnomalousBehavior(activity UserActivity) {
	for _, handler := range bas.anomalyHandlers {
		handler(activity)
	}
}

// logAnomalousBehavior logs the anomalous behavior details
func logAnomalousBehavior(activity UserActivity) {
	log.Printf("Anomalous behavior detected: %+v\n", activity)
}

// notifySecurityTeam sends a notification to the security team
func notifySecurityTeam(activity UserActivity) {
	// Example notification (extend with real notification logic)
	log.Printf("Notifying security team of anomalous behavior: %+v\n", activity)
}

// restrictAccount restricts the account associated with anomalous behavior
func restrictAccount(activity UserActivity) {
	// Example restriction logic (extend with real account restriction logic)
	log.Printf("Restricting account associated with user activity: %s\n", activity.UserID)
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

