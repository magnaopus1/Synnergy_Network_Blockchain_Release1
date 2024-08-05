package security

import (
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/utils"
)

// ComplianceManager manages regulatory compliance for SYN223 tokens.
type ComplianceManager struct {
	mu                sync.RWMutex
	kycRegistry       map[string]KYCInfo
	transactionLimits map[string]TransactionLimit
	reportingLogs     []ComplianceReport
}

// KYCInfo contains information for Know Your Customer (KYC) compliance.
type KYCInfo struct {
	CustomerID string
	Verified   bool
	Timestamp  time.Time
}

// TransactionLimit sets transaction limits for different roles.
type TransactionLimit struct {
	Role         string
	DailyLimit   uint64
	MonthlyLimit uint64
}

// ComplianceReport logs compliance-related activities.
type ComplianceReport struct {
	Activity    string
	CustomerID  string
	Timestamp   time.Time
	Description string
}

// NewComplianceManager initializes a new ComplianceManager instance.
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		kycRegistry:       make(map[string]KYCInfo),
		transactionLimits: make(map[string]TransactionLimit),
		reportingLogs:     []ComplianceReport{},
	}
}

// AddKYCInfo adds or updates KYC information for a customer.
func (cm *ComplianceManager) AddKYCInfo(customerID string, verified bool) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.kycRegistry[customerID] = KYCInfo{
		CustomerID: customerID,
		Verified:   verified,
		Timestamp:  time.Now(),
	}
	cm.logComplianceActivity("AddKYCInfo", customerID, "KYC information added or updated")
	return nil
}

// VerifyKYC checks if a customer has verified KYC information.
func (cm *ComplianceManager) VerifyKYC(customerID string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	kycInfo, exists := cm.kycRegistry[customerID]
	return exists && kycInfo.Verified
}

// SetTransactionLimit sets transaction limits for a specific role.
func (cm *ComplianceManager) SetTransactionLimit(role string, dailyLimit, monthlyLimit uint64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.transactionLimits[role] = TransactionLimit{
		Role:         role,
		DailyLimit:   dailyLimit,
		MonthlyLimit: monthlyLimit,
	}
	cm.logComplianceActivity("SetTransactionLimit", role, "Transaction limits set")
	return nil
}

// CheckTransactionLimit checks if a transaction exceeds set limits for a role.
func (cm *ComplianceManager) CheckTransactionLimit(role string, amount uint64, period string) (bool, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	limit, exists := cm.transactionLimits[role]
	if !exists {
		return false, errors.New("transaction limit not set for role")
	}

	switch period {
	case "daily":
		return amount <= limit.DailyLimit, nil
	case "monthly":
		return amount <= limit.MonthlyLimit, nil
	default:
		return false, errors.New("invalid period specified")
	}
}

// GenerateComplianceReport generates a compliance report for a specific activity.
func (cm *ComplianceManager) GenerateComplianceReport(activity, customerID, description string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.reportingLogs = append(cm.reportingLogs, ComplianceReport{
		Activity:    activity,
		CustomerID:  customerID,
		Timestamp:   time.Now(),
		Description: description,
	})
}

// GetComplianceReports retrieves all compliance reports.
func (cm *ComplianceManager) GetComplianceReports() []ComplianceReport {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.reportingLogs
}

// EncryptKYCData encrypts KYC information for a customer using a specified encryption technique.
func (cm *ComplianceManager) EncryptKYCData(customerID, passphrase string) (string, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	kycInfo, exists := cm.kycRegistry[customerID]
	if !exists {
		return "", errors.New("customer not found")
	}

	// Serialize KYC data to JSON
	jsonData, err := utils.ToJSON(kycInfo)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptKYCData decrypts KYC information for a customer using a specified decryption technique.
func (cm *ComplianceManager) DecryptKYCData(encryptedData, passphrase string) (KYCInfo, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return KYCInfo{}, err
	}

	// Deserialize JSON data to KYCInfo
	var kycInfo KYCInfo
	err = utils.FromJSON(decryptedData, &kycInfo)
	if err != nil {
		return KYCInfo{}, err
	}

	return kycInfo, nil
}

// logComplianceActivity logs compliance-related activities.
func (cm *ComplianceManager) logComplianceActivity(activity, customerID, description string) {
	cm.reportingLogs = append(cm.reportingLogs, ComplianceReport{
		Activity:    activity,
		CustomerID:  customerID,
		Timestamp:   time.Now(),
		Description: description,
	})
}
