package multi_factor_authentication

import (
	"errors"
	"fmt"
	"time"
)

// VerificationFactor represents a type of verification factor in the MFA system.
type VerificationFactor struct {
	Type       string
	Value      string
	Validated  bool
	LastUsed   time.Time
}

// User represents a user in the Synnergy Network with MFA enabled.
type User struct {
	ID                string
	Password          string
	PrivateKey        string
	VerificationFactors []VerificationFactor
	RiskScore         float64
}

// MFAService provides multi-factor authentication services.
type MFAService struct {
	Users map[string]*User
}

// NewMFAService creates a new MFAService.
func NewMFAService() *MFAService {
	return &MFAService{
		Users: make(map[string]*User),
	}
}

// AddUser adds a new user to the MFAService.
func (service *MFAService) AddUser(user *User) {
	service.Users[user.ID] = user
}

// ValidateVerificationFactor validates a verification factor for a user.
func (service *MFAService) ValidateVerificationFactor(userID, factorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if factor.Type == factorType && factor.Value == factorValue {
			user.VerificationFactors[i].Validated = true
			user.VerificationFactors[i].LastUsed = time.Now()
			return nil
		}
	}
	return errors.New("verification factor not found or invalid")
}

// IsTransactionAuthorized checks if a transaction is authorized based on MFA.
func (service *MFAService) IsTransactionAuthorized(userID string, requiredFactors int) bool {
	user, exists := service.Users[userID]
	if !exists {
		return false
	}

	validatedCount := 0
	for _, factor := range user.VerificationFactors {
		if factor.Validated {
			validatedCount++
		}
		if validatedCount >= requiredFactors {
			return true
		}
	}
	return false
}

// AdaptiveRiskAssessment assesses the risk of a transaction and applies additional verification if necessary.
func (service *MFAService) AdaptiveRiskAssessment(userID string, transactionAmount float64) (bool, error) {
	user, exists := service.Users[userID]
	if !exists {
		return false, errors.New("user not found")
	}

	// Simple risk assessment based on transaction amount and user risk score
	riskThreshold := 1000.0
	if transactionAmount > riskThreshold || user.RiskScore > 0.5 {
		fmt.Println("High risk transaction, additional verification required")
		return false, nil
	}
	return true, nil
}

// ResetVerificationFactors resets the validation status of verification factors after a transaction.
func (service *MFAService) ResetVerificationFactors(userID string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i := range user.VerificationFactors {
		user.VerificationFactors[i].Validated = false
	}
	return nil
}

// Example usage
func main() {
	// Create an MFAService
	mfaService := NewMFAService()

	// Add a user
	user := &User{
		ID:         "user1",
		Password:   "password123",
		PrivateKey: "private_key_abc",
		VerificationFactors: []VerificationFactor{
			{Type: "password", Value: "password123"},
			{Type: "token", Value: "token456"},
			{Type: "biometric", Value: "fingerprint789"},
		},
		RiskScore: 0.3,
	}
	mfaService.AddUser(user)

	// Validate verification factors
	err := mfaService.ValidateVerificationFactor("user1", "password", "password123")
	if err != nil {
		fmt.Println("Error:", err)
	}

	err = mfaService.ValidateVerificationFactor("user1", "token", "token456")
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Check if transaction is authorized
	isAuthorized := mfaService.IsTransactionAuthorized("user1", 2)
	fmt.Println("Transaction authorized:", isAuthorized)

	// Perform adaptive risk assessment
	isLowRisk, err := mfaService.AdaptiveRiskAssessment("user1", 500)
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Transaction low risk:", isLowRisk)

	// Reset verification factors after transaction
	err = mfaService.ResetVerificationFactors("user1")
	if err != nil {
		fmt.Println("Error:", err)
	}
}
