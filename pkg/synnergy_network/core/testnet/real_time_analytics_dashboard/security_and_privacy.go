package real_time_analytics_dashboard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// SecurityManager manages the security aspects of the real-time analytics dashboard
type SecurityManager struct {
	encryptionKey []byte
	mutex         sync.RWMutex
}

// NewSecurityManager initializes a new SecurityManager with a given encryption key
func NewSecurityManager(key string) (*SecurityManager, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes long")
	}
	return &SecurityManager{
		encryptionKey: []byte(key),
	}, nil
}

// EncryptData encrypts the given data using AES encryption
func (sm *SecurityManager) EncryptData(data string) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given data using AES encryption
func (sm *SecurityManager) DecryptData(data string) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AuditLog represents a security audit log entry
type AuditLog struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	UserID    string    `json:"user_id"`
	Details   string    `json:"details"`
}

// AuditManager manages audit logs for security events
type AuditManager struct {
	logs  []AuditLog
	mutex sync.RWMutex
}

// NewAuditManager initializes a new AuditManager
func NewAuditManager() *AuditManager {
	return &AuditManager{
		logs: make([]AuditLog, 0),
	}
}

// AddLog adds a new audit log entry
func (am *AuditManager) AddLog(event, userID, details string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.logs = append(am.logs, AuditLog{
		Timestamp: time.Now(),
		Event:     event,
		UserID:    userID,
		Details:   details,
	})
}

// GetLogs retrieves all audit log entries
func (am *AuditManager) GetLogs() []AuditLog {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	return am.logs
}

// DataPrivacyManager manages data privacy aspects, such as access control and anonymization
type DataPrivacyManager struct {
	allowedUsers map[string]bool
	mutex        sync.RWMutex
}

// NewDataPrivacyManager initializes a new DataPrivacyManager
func NewDataPrivacyManager() *DataPrivacyManager {
	return &DataPrivacyManager{
		allowedUsers: make(map[string]bool),
	}
}

// GrantAccess grants access to a specific user
func (dpm *DataPrivacyManager) GrantAccess(userID string) {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()
	dpm.allowedUsers[userID] = true
}

// RevokeAccess revokes access for a specific user
func (dpm *DataPrivacyManager) RevokeAccess(userID string) {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()
	delete(dpm.allowedUsers, userID)
}

// CheckAccess checks if a specific user has access
func (dpm *DataPrivacyManager) CheckAccess(userID string) bool {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()
	return dpm.allowedUsers[userID]
}

// AnonymizeData anonymizes the given data
func (dpm *DataPrivacyManager) AnonymizeData(data string) string {
	// Implement anonymization logic as needed, e.g., masking PII
	return "anonymized_" + data
}

// SecurityAndPrivacyManager manages security and privacy aspects of the dashboard
type SecurityAndPrivacyManager struct {
	SecurityManager    *SecurityManager
	AuditManager       *AuditManager
	DataPrivacyManager *DataPrivacyManager
}

// NewSecurityAndPrivacyManager initializes a new SecurityAndPrivacyManager
func NewSecurityAndPrivacyManager(encryptionKey string) (*SecurityAndPrivacyManager, error) {
	securityManager, err := NewSecurityManager(encryptionKey)
	if err != nil {
		return nil, err
	}
	return &SecurityAndPrivacyManager{
		SecurityManager:    securityManager,
		AuditManager:       NewAuditManager(),
		DataPrivacyManager: NewDataPrivacyManager(),
	}, nil
}

// Example integration function for SecurityAndPrivacyManager
func integrateSecurityAndPrivacyManager() {
	spm, err := NewSecurityAndPrivacyManager("a very very very very secret key!!")
	if err != nil {
		fmt.Println("Failed to initialize SecurityAndPrivacyManager:", err)
		return
	}

	// Example usage of the SecurityAndPrivacyManager
	encryptedData, err := spm.SecurityManager.EncryptData("sensitive data")
	if err != nil {
		fmt.Println("Failed to encrypt data:", err)
		return
	}

	decryptedData, err := spm.SecurityManager.DecryptData(encryptedData)
	if err != nil {
		fmt.Println("Failed to decrypt data:", err)
		return
	}

	fmt.Println("Decrypted data:", decryptedData)
	spm.AuditManager.AddLog("data_encryption", "user123", "Encrypted sensitive data")
	logs := spm.AuditManager.GetLogs()
	fmt.Println("Audit logs:", logs)

	spm.DataPrivacyManager.GrantAccess("user123")
	hasAccess := spm.DataPrivacyManager.CheckAccess("user123")
	fmt.Println("User has access:", hasAccess)

	anonymizedData := spm.DataPrivacyManager.AnonymizeData("sensitive data")
	fmt.Println("Anonymized data:", anonymizedData)
}
