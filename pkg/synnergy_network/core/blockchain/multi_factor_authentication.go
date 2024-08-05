package multi_factor_authentication

import (
	"errors"
	"fmt"
	"time"
)

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

// HashAndSalt generates a hash for the given value with a salt.
func HashAndSalt(value string) (string, []byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", nil, err
	}

	hash, err := scrypt.Key([]byte(value), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", nil, err
	}

	return fmt.Sprintf("%x", hash), salt, nil
}

// ValidateFactor validates a verification factor for a user.
func (service *MFAService) ValidateFactor(userID, factorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if string(factor.Type) == factorType {
			hash, err := scrypt.Key([]byte(factorValue), factor.Salt, 16384, 8, 1, 32)
			if err != nil {
				return err
			}
			if fmt.Sprintf("%x", hash) == factor.Value {
				user.VerificationFactors[i].Value = fmt.Sprintf("%x", hash)
				return nil
			}
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
		if factor.Value != "" {
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

	riskThreshold := 1000.0
	if transactionAmount > riskThreshold {
		fmt.Println("High risk transaction, additional verification required")
		return false, nil
	}
	return true, nil
}

// ResetFactors resets the validation status of verification factors after a transaction.
func (service *MFAService) ResetFactors(userID string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i := range user.VerificationFactors {
		user.VerificationFactors[i].Value = ""
	}
	return nil
}

// AddFactor adds a new verification factor for a user.
func (service *MFAService) AddFactor(userID string, factorType MFAFactorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	hashedValue, salt, err := HashAndSalt(factorValue)
	if err != nil {
		return err
	}

	factor := MFAFactor{
		Type:  factorType,
		Value: hashedValue,
		Salt:  salt,
	}

	user.VerificationFactors = append(user.VerificationFactors, factor)
	return nil
}

// RemoveFactor removes a verification factor for a user.
func (service *MFAService) RemoveFactor(userID string, factorType MFAFactorType) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if factor.Type == factorType {
			user.VerificationFactors = append(user.VerificationFactors[:i], user.VerificationFactors[i+1:]...)
			return nil
		}
	}
	return errors.New("verification factor not found")
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

// HashAndSalt generates a hash for the given value with a salt.
func HashAndSalt(value string) (string, []byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", nil, err
	}

	hash, err := scrypt.Key([]byte(value), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", nil, err
	}

	return fmt.Sprintf("%x", hash), salt, nil
}

// ValidateFactor validates a verification factor for a user.
func (service *MFAService) ValidateFactor(userID, factorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if string(factor.Type) == factorType {
			hash, err := scrypt.Key([]byte(factorValue), factor.Salt, 16384, 8, 1, 32)
			if err != nil {
				return err
			}
			if fmt.Sprintf("%x", hash) == factor.Value {
				user.VerificationFactors[i].Value = fmt.Sprintf("%x", hash)
				return nil
			}
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
		if factor.Value != "" {
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

	riskThreshold := 1000.0
	if transactionAmount > riskThreshold {
		fmt.Println("High risk transaction, additional verification required")
		return false, nil
	}
	return true, nil
}

// ResetFactors resets the validation status of verification factors after a transaction.
func (service *MFAService) ResetFactors(userID string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i := range user.VerificationFactors {
		user.VerificationFactors[i].Value = ""
	}
	return nil
}

// AddFactor adds a new verification factor for a user.
func (service *MFAService) AddFactor(userID string, factorType MFAFactorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	hashedValue, salt, err := HashAndSalt(factorValue)
	if err != nil {
		return err
	}

	factor := MFAFactor{
		Type:  factorType,
		Value: hashedValue,
		Salt:  salt,
	}

	user.VerificationFactors = append(user.VerificationFactors, factor)
	return nil
}

// RemoveFactor removes a verification factor for a user.
func (service *MFAService) RemoveFactor(userID string, factorType MFAFactorType) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if factor.Type == factorType {
			user.VerificationFactors = append(user.VerificationFactors[:i], user.VerificationFactors[i+1:]...)
			return nil
		}
	}
	return errors.New("verification factor not found")
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

// HashAndSalt generates a hash for the given value with a salt.
func HashAndSalt(value string) (string, []byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", nil, err
	}

	hash, err := scrypt.Key([]byte(value), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", nil, err
	}

	return fmt.Sprintf("%x", hash), salt, nil
}

// ValidateFactor validates a verification factor for a user.
func (service *MFAService) ValidateFactor(userID, factorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if string(factor.Type) == factorType {
			hash, err := scrypt.Key([]byte(factorValue), factor.Salt, 16384, 8, 1, 32)
			if err != nil {
				return err
			}
			if fmt.Sprintf("%x", hash) == factor.Value {
				user.VerificationFactors[i].Value = fmt.Sprintf("%x", hash)
				return nil
			}
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
		if factor.Value != "" {
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

	riskThreshold := 1000.0
	if transactionAmount > riskThreshold {
		fmt.Println("High risk transaction, additional verification required")
		return false, nil
	}
	return true, nil
}

// ResetFactors resets the validation status of verification factors after a transaction.
func (service *MFAService) ResetFactors(userID string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i := range user.VerificationFactors {
		user.VerificationFactors[i].Value = ""
	}
	return nil
}

// AddFactor adds a new verification factor for a user.
func (service *MFAService) AddFactor(userID string, factorType MFAFactorType, factorValue string) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	hashedValue, salt, err := HashAndSalt(factorValue)
	if err != nil {
		return err
	}

	factor := MFAFactor{
		Type:  factorType,
		Value: hashedValue,
		Salt:  salt,
	}

	user.VerificationFactors = append(user.VerificationFactors, factor)
	return nil
}

// RemoveFactor removes a verification factor for a user.
func (service *MFAService) RemoveFactor(userID string, factorType MFAFactorType) error {
	user, exists := service.Users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, factor := range user.VerificationFactors {
		if factor.Type == factorType {
			user.VerificationFactors = append(user.VerificationFactors[:i], user.VerificationFactors[i+1:]...)
			return nil
		}
	}
	return errors.New("verification factor not found")
}

