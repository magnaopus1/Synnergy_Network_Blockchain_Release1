package multi_factor_authentication

import (
	"testing"
)

func TestHashAndSalt(t *testing.T) {
	value := "test_value"
	hashedValue, salt, err := HashAndSalt(value)
	if err != nil {
		t.Fatalf("Failed to hash and salt value: %v", err)
	}

	if hashedValue == "" || len(salt) == 0 {
		t.Fatalf("Hash and salt should not be empty")
	}
}

func TestAddUser(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	if mfaService.Users[user.ID] == nil {
		t.Fatalf("User should be added to the service")
	}
}

func TestAddFactor(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	err := mfaService.AddFactor("user1", PasswordFactor, "password123")
	if err != nil {
		t.Fatalf("Failed to add factor: %v", err)
	}

	if len(user.VerificationFactors) != 1 {
		t.Fatalf("Factor should be added to the user")
	}
}

func TestValidateFactor(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	err := mfaService.AddFactor("user1", PasswordFactor, "password123")
	if err != nil {
		t.Fatalf("Failed to add factor: %v", err)
	}

	err = mfaService.ValidateFactor("user1", string(PasswordFactor), "password123")
	if err != nil {
		t.Fatalf("Failed to validate factor: %v", err)
	}
}

func TestIsTransactionAuthorized(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	err := mfaService.AddFactor("user1", PasswordFactor, "password123")
	if err != nil {
		t.Fatalf("Failed to add factor: %v", err)
	}
	err = mfaService.ValidateFactor("user1", string(PasswordFactor), "password123")
	if err != nil {
		t.Fatalf("Failed to validate factor: %v", err)
	}

	isAuthorized := mfaService.IsTransactionAuthorized("user1", 1)
	if !isAuthorized {
		t.Fatalf("Transaction should be authorized with one valid factor")
	}

	isAuthorized = mfaService.IsTransactionAuthorized("user1", 2)
	if isAuthorized {
		t.Fatalf("Transaction should not be authorized with insufficient factors")
	}
}

func TestAdaptiveRiskAssessment(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	isLowRisk, err := mfaService.AdaptiveRiskAssessment("user1", 500)
	if err != nil {
		t.Fatalf("Failed to assess risk: %v", err)
	}
	if !isLowRisk {
		t.Fatalf("Transaction should be considered low risk")
	}

	isHighRisk, err := mfaService.AdaptiveRiskAssessment("user1", 1500)
	if err != nil {
		t.Fatalf("Failed to assess risk: %v", err)
	}
	if isHighRisk {
		t.Fatalf("Transaction should be considered high risk")
	}
}

func TestResetFactors(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	err := mfaService.AddFactor("user1", PasswordFactor, "password123")
	if err != nil {
		t.Fatalf("Failed to add factor: %v", err)
	}
	err = mfaService.ValidateFactor("user1", string(PasswordFactor), "password123")
	if err != nil {
		t.Fatalf("Failed to validate factor: %v", err)
	}

	err = mfaService.ResetFactors("user1")
	if err != nil {
		t.Fatalf("Failed to reset factors: %v", err)
	}

	if user.VerificationFactors[0].Value != "" {
		t.Fatalf("Factors should be reset after transaction")
	}
}

func TestRemoveFactor(t *testing.T) {
	mfaService := NewMFAService()
	user := &User{
		ID:         "user1",
		PrivateKey: "private_key_abc",
	}
	mfaService.AddUser(user)

	err := mfaService.AddFactor("user1", PasswordFactor, "password123")
	if err != nil {
		t.Fatalf("Failed to add factor: %v", err)
	}

	err = mfaService.RemoveFactor("user1", PasswordFactor)
	if err != nil {
		t.Fatalf("Failed to remove factor: %v", err)
	}

	if len(user.VerificationFactors) != 0 {
		t.Fatalf("Factor should be removed from the user")
	}
}
