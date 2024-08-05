package transaction_monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"golang.org/x/crypto/argon2"
)


// NewAnomalyDetectionSystem initializes a new anomaly detection system
func NewAnomalyDetectionSystem(db *sql.DB) *AnomalyDetectionSystem {
	return &AnomalyDetectionSystem{
		db: db,
		anomalyHandlers: []func(Anomaly){
			logAnomaly,
			notifyCompliance,
			blockSuspiciousAccount,
		},
	}
}

// MonitorTransactions starts the transaction monitoring process
func (ads *AnomalyDetectionSystem) MonitorTransactions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ads.checkForAnomalies()
		case <-ctx.Done():
			return
		}
	}
}

// checkForAnomalies fetches recent transactions and checks for anomalies
func (ads *AnomalyDetectionSystem) checkForAnomalies() {
	transactions, err := ads.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	for _, tx := range transactions {
		if ads.isAnomalous(tx) {
			anomaly := Anomaly{
				TransactionID: tx.ID,
				DetectedAt:    time.Now(),
				Reason:        "Anomalous transaction detected",
			}
			ads.handleAnomaly(anomaly)
		}
	}
}

// fetchRecentTransactions retrieves recent transactions from the database
func (ads *AnomalyDetectionSystem) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := ads.db.Query(`
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
func (ads *AnomalyDetectionSystem) isAnomalous(tx Transaction) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if math.Abs(tx.Amount) > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}

// handleAnomaly processes a detected anomaly
func (ads *AnomalyDetectionSystem) handleAnomaly(anomaly Anomaly) {
	for _, handler := range ads.anomalyHandlers {
		handler(anomaly)
	}
}

// logAnomaly logs the anomaly details
func logAnomaly(anomaly Anomaly) {
	log.Printf("Anomaly detected: %+v\n", anomaly)
}

// notifyCompliance sends a notification to the compliance team
func notifyCompliance(anomaly Anomaly) {
	// Example notification (extend with real notification logic)
	log.Printf("Notifying compliance team of anomaly: %+v\n", anomaly)
}

// blockSuspiciousAccount blocks the account associated with a suspicious transaction
func blockSuspiciousAccount(anomaly Anomaly) {
	// Example blocking logic (extend with real account blocking logic)
	log.Printf("Blocking account associated with transaction: %s\n", anomaly.TransactionID)
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
	// Implement AES encryption logic here
	return nil, errors.New("encryption not implemented")
}

func decrypt(encryptedData, passphrase []byte) ([]byte, error) {
	// Use AES for decryption
	// Implement AES decryption logic here
	return nil, errors.New("decryption not implemented")
}

// Ensure secure communication between services
func secureCommunication() {
	// Implement secure communication logic here
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


// NewConcurrencyHandler initializes a new concurrency handler
func NewConcurrencyHandler(db *sql.DB) *ConcurrencyHandler {
	return &ConcurrencyHandler{
		db: db,
		anomalyHandlers: []func(Anomaly){
			logAnomaly,
			notifyCompliance,
			blockSuspiciousAccount,
		},
		activityHandlers: []func(UserActivity){
			logUserActivity,
			notifySecurityTeam,
			restrictAccount,
		},
	}
}

// StartMonitoring starts the transaction and user activity monitoring processes
func (ch *ConcurrencyHandler) StartMonitoring(ctx context.Context) {
	ch.wg.Add(2)
	go ch.monitorTransactions(ctx)
	go ch.monitorUserActivities(ctx)
	ch.wg.Wait()
}

// monitorTransactions starts the transaction monitoring process
func (ch *ConcurrencyHandler) monitorTransactions(ctx context.Context) {
	defer ch.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ch.checkForAnomalies()
		case <-ctx.Done():
			return
		}
	}
}

// monitorUserActivities starts the user activity monitoring process
func (ch *ConcurrencyHandler) monitorUserActivities(ctx context.Context) {
	defer ch.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ch.checkForAnomalousBehavior()
		case <-ctx.Done():
			return
		}
	}
}

// checkForAnomalies fetches recent transactions and checks for anomalies
func (ch *ConcurrencyHandler) checkForAnomalies() {
	transactions, err := ch.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	for _, tx := range transactions {
		if ch.isAnomalous(tx) {
			anomaly := Anomaly{
				TransactionID: tx.ID,
				DetectedAt:    time.Now(),
				Reason:        "Anomalous transaction detected",
			}
			ch.handleAnomaly(anomaly)
		}
	}
}

// fetchRecentTransactions retrieves recent transactions from the database
func (ch *ConcurrencyHandler) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := ch.db.Query(`
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
func (ch *ConcurrencyHandler) isAnomalous(tx Transaction) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}

// handleAnomaly processes a detected anomaly
func (ch *ConcurrencyHandler) handleAnomaly(anomaly Anomaly) {
	for _, handler := range ch.anomalyHandlers {
		handler(anomaly)
	}
}

// checkForAnomalousBehavior fetches recent user activities and checks for anomalies
func (ch *ConcurrencyHandler) checkForAnomalousBehavior() {
	activities, err := ch.fetchRecentUserActivities()
	if err != nil {
		log.Println("Error fetching user activities:", err)
		return
	}

	for _, activity := range activities {
		if ch.isAnomalousActivity(activity) {
			ch.handleAnomalousActivity(activity)
		}
	}
}

// fetchRecentUserActivities retrieves recent user activities from the database
func (ch *ConcurrencyHandler) fetchRecentUserActivities() ([]UserActivity, error) {
	rows, err := ch.db.Query(`
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

// isAnomalousActivity determines if a user activity is anomalous based on predefined criteria
func (ch *ConcurrencyHandler) isAnomalousActivity(activity UserActivity) bool {
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

// handleAnomalousActivity processes a detected anomalous user activity
func (ch *ConcurrencyHandler) handleAnomalousActivity(activity UserActivity) {
	for _, handler := range ch.activityHandlers {
		handler(activity)
	}
}

// logAnomaly logs the anomaly details
func logAnomaly(anomaly Anomaly) {
	log.Printf("Anomaly detected: %+v\n", anomaly)
}

// notifyCompliance sends a notification to the compliance team
func notifyCompliance(anomaly Anomaly) {
	// Example notification (extend with real notification logic)
	log.Printf("Notifying compliance team of anomaly: %+v\n", anomaly)
}

// blockSuspiciousAccount blocks the account associated with a suspicious transaction
func blockSuspiciousAccount(anomaly Anomaly) {
	// Example blocking logic (extend with real account blocking logic)
	log.Printf("Blocking account associated with transaction: %s\n", anomaly.TransactionID)
}

// logUserActivity logs the user activity details
func logUserActivity(activity UserActivity) {
	log.Printf("User activity detected: %+v\n", activity)
}

// notifySecurityTeam sends a notification to the security team
func notifySecurityTeam(activity UserActivity) {
	// Example notification (extend with real notification logic)
	log.Printf("Notifying security team of anomalous activity: %+v\n", activity)
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


// NewStructuredStorageSystem initializes a new structured storage system
func NewStructuredStorageSystem(db *sql.DB) *StructuredStorageSystem {
	return &StructuredStorageSystem{db: db}
}

// StoreTransaction stores a new transaction in the database
func (sss *StructuredStorageSystem) StoreTransaction(tx Transaction) error {
	_, err := sss.db.Exec(`
		INSERT INTO transactions (id, user_id, timestamp, amount, type, status) 
		VALUES ($1, $2, $3, $4, $5, $6)`,
		tx.ID, tx.UserID, tx.Timestamp, tx.Amount, tx.Type, tx.Status)
	return err
}

// QueryTransactions retrieves transactions based on specific criteria
func (sss *StructuredStorageSystem) QueryTransactions(userID string, startTime, endTime time.Time, minAmount, maxAmount float64) ([]Transaction, error) {
	rows, err := sss.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions 
		WHERE user_id = $1 
		AND timestamp BETWEEN $2 AND $3 
		AND amount BETWEEN $4 AND $5`,
		userID, startTime, endTime, minAmount, maxAmount)
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

// QueryAllTransactions retrieves all transactions
func (sss *StructuredStorageSystem) QueryAllTransactions() ([]Transaction, error) {
	rows, err := sss.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions`)
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

// DeleteTransaction deletes a transaction by ID
func (sss *StructuredStorageSystem) DeleteTransaction(transactionID string) error {
	_, err := sss.db.Exec(`
		DELETE FROM transactions WHERE id = $1`, transactionID)
	return err
}

// Example usage of transaction monitoring using concurrency with Goroutines and Channels
func (sss *StructuredStorageSystem) MonitorTransactions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			transactions, err := sss.QueryAllTransactions()
			if err != nil {
				log.Println("Error querying transactions:", err)
				continue
			}
			for _, tx := range transactions {
				if sss.isAnomalous(tx) {
					log.Println("Anomalous transaction detected:", tx)
					// Handle the anomalous transaction (e.g., alert, flag, etc.)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// isAnomalous determines if a transaction is anomalous based on predefined criteria
func (sss *StructuredStorageSystem) isAnomalous(tx Transaction) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}



// NewTransactionClassifier initializes a new transaction classifier
func NewTransactionClassifier(db *sql.DB, classifyFunc func(Transaction) string) *TransactionClassifier {
	return &TransactionClassifier{
		db:           db,
		classifyFunc: classifyFunc,
	}
}

// Start begins the transaction classification process
func (tc *TransactionClassifier) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.classifyRecentTransactions()
		case <-ctx.Done():
			return
		}
	}
}

// classifyRecentTransactions fetches recent transactions and classifies them
func (tc *TransactionClassifier) classifyRecentTransactions() {
	transactions, err := tc.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	for _, tx := range transactions {
		tx.Category = tc.classifyFunc(tx)
		if err := tc.updateTransactionCategory(tx); err != nil {
			log.Println("Error updating transaction category:", err)
		}
	}
}

// fetchRecentTransactions retrieves recent transactions from the database
func (tc *TransactionClassifier) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := tc.db.Query(`
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

// updateTransactionCategory updates the category of a transaction in the database
func (tc *TransactionClassifier) updateTransactionCategory(tx Transaction) error {
	_, err := tc.db.Exec(`
		UPDATE transactions 
		SET category = $1 
		WHERE id = $2`,
		tx.Category, tx.ID)
	return err
}

// Example classifyFunc that classifies transactions based on predefined rules
func classifyTransaction(tx Transaction) string {
	// Example classification logic (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 {
		return "Large Transaction"
	}
	if tx.Type == "withdrawal" {
		return "Withdrawal"
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return "Normal"
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


// NewTransactionMonitoringSystem initializes a new transaction monitoring system
func NewTransactionMonitoringSystem(db *sql.DB, natsURL string, classifyFunc func(Transaction) string) (*TransactionMonitoringSystem, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}
	return &TransactionMonitoringSystem{
		db:           db,
		natsConn:     nc,
		alertCh:      make(chan Anomaly, 100),
		classifyFunc: classifyFunc,
		model:        NewPredictiveModel(),
	}, nil
}

// Start begins the transaction monitoring process
func (tms *TransactionMonitoringSystem) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tms.monitorTransactions()
		case <-ctx.Done():
			tms.natsConn.Close()
			close(tms.alertCh)
			return
		}
	}
}

// monitorTransactions fetches and processes recent transactions
func (tms *TransactionMonitoringSystem) monitorTransactions() {
	transactions, err := tms.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	var wg sync.WaitGroup
	for _, tx := range transactions {
		wg.Add(1)
		go func(tx Transaction) {
			defer wg.Done()
			tms.processTransaction(tx)
		}(tx)
	}
	wg.Wait()
}

// processTransaction processes a single transaction
func (tms *TransactionMonitoringSystem) processTransaction(tx Transaction) {
	tx.Category = tms.classifyFunc(tx)
	if tms.isAnomalous(tx) {
		anomaly := Anomaly{
			TransactionID: tx.ID,
			DetectedAt:    time.Now(),
			Reason:        "Anomalous transaction detected",
		}
		tms.alertCh <- anomaly
	}

	if err := tms.updateTransactionCategory(tx); err != nil {
		log.Println("Error updating transaction category:", err)
	}
}

// fetchRecentTransactions retrieves recent transactions from the database
func (tms *TransactionMonitoringSystem) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := tms.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status, category 
		FROM transactions 
		WHERE timestamp > NOW() - INTERVAL '1 MINUTE'`)
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

// updateTransactionCategory updates the category of a transaction in the database
func (tms *TransactionMonitoringSystem) updateTransactionCategory(tx Transaction) error {
	_, err := tms.db.Exec(`
		UPDATE transactions 
		SET category = $1 
		WHERE id = $2`,
		tx.Category, tx.ID)
	return err
}

// isAnomalous determines if a transaction is anomalous based on predefined criteria
func (tms *TransactionMonitoringSystem) isAnomalous(tx Transaction) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}

// ServeDashboard serves the dashboard data via an HTTP endpoint
func (tms *TransactionMonitoringSystem) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	tms.dataLock.Lock()
	defer tms.dataLock.Unlock()

	data, err := json.Marshal(tms.dashboardData)
	if err != nil {
		http.Error(w, "Error marshalling dashboard data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// updateDashboardData updates the data displayed on the dashboard
func (tms *TransactionMonitoringSystem) updateDashboardData() {
	tms.dataLock.Lock()
	defer tms.dataLock.Unlock()

	totalTransactions, err := tms.getTotalTransactions()
	if err != nil {
		log.Println("Error getting total transactions:", err)
		return
	}

	anomalies, err := tms.getRecentAnomalies()
	if err != nil {
		log.Println("Error getting recent anomalies:", err)
		return
	}

	recentTransactions, err := tms.getRecentTransactions()
	if err != nil {
		log.Println("Error getting recent transactions:", err)
		return
	}

	tms.dashboardData = DashboardData{
		TotalTransactions: totalTransactions,
		Anomalies:         anomalies,
		RecentTransactions: recentTransactions,
	}
}

// getTotalTransactions retrieves the total number of transactions from the database
func (tms *TransactionMonitoringSystem) getTotalTransactions() (int, error) {
	var total int
	err := tms.db.QueryRow(`
		SELECT COUNT(*) 
		FROM transactions`).Scan(&total)
	return total, err
}

// getRecentAnomalies retrieves recent anomalies from the database
func (tms *TransactionMonitoringSystem) getRecentAnomalies() ([]Anomaly, error) {
	rows, err := tms.db.Query(`
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
func (tms *TransactionMonitoringSystem) getRecentTransactions() ([]Transaction, error) {
	rows, err := tms.db.Query(`
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

// PredictiveModel represents the predictive model for transaction monitoring
type PredictiveModel struct {
	// Add model fields here
}

// NewPredictiveModel initializes a new predictive model
func NewPredictiveModel() *PredictiveModel {
	return &PredictiveModel{
		// Initialize model fields here
	}
}

// Predict predicts if a transaction is suspicious
func (pm *PredictiveModel) Predict(tx Transaction) bool {
	// Add prediction logic here
	return false
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


