package security

import (
	"fmt"
	"sync"
	"time"
)

// MFAType represents the type of multi-factor authentication
type MFAType string

const (
	MFATypeSMS     MFAType = "SMS"
	MFATypeEmail   MFAType = "Email"
	MFATypeTOTP    MFAType = "TOTP"    // Time-based One-Time Password
	MFATypeU2F     MFAType = "U2F"     // Universal 2nd Factor (hardware token)
	MFATypeBackup  MFAType = "Backup"  // Backup codes
)

// MFASetup contains the details required to set up a multi-factor authentication method
type MFASetup struct {
	UserID    string
	MFAType   MFAType
	Details   string    // Can be phone number, email, TOTP secret, etc.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MFAVerification stores the verification data for an MFA attempt
type MFAVerification struct {
	UserID    string
	MFAType   MFAType
	Code      string
	ExpiresAt time.Time
}

// MFAManager manages multi-factor authentication for SYN721 tokens
type MFAManager struct {
	mfaSetups        map[string]MFASetup
	mfaVerifications map[string]MFAVerification
	mutex            sync.Mutex
}

// NewMFAManager initializes a new MFAManager
func NewMFAManager() *MFAManager {
	return &MFAManager{
		mfaSetups:        make(map[string]MFASetup),
		mfaVerifications: make(map[string]MFAVerification),
	}
}

// SetupMFA sets up a multi-factor authentication method for a user
func (mfa *MFAManager) SetupMFA(userID string, mfaType MFAType, details string) error {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	setup := MFASetup{
		UserID:    userID,
		MFAType:   mfaType,
		Details:   details,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mfa.mfaSetups[userID] = setup
	return nil
}

// GetMFASetup retrieves the MFA setup for a user
func (mfa *MFAManager) GetMFASetup(userID string) (MFASetup, error) {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	setup, exists := mfa.mfaSetups[userID]
	if !exists {
		return MFASetup{}, fmt.Errorf("no MFA setup found for user ID %s", userID)
	}

	return setup, nil
}

// RemoveMFA removes the MFA setup for a user
func (mfa *MFAManager) RemoveMFA(userID string) error {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	delete(mfa.mfaSetups, userID)
	return nil
}

// InitiateMFAVerification initiates an MFA verification process for a user
func (mfa *MFAManager) InitiateMFAVerification(userID string, mfaType MFAType, code string) error {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	verification := MFAVerification{
		UserID:    userID,
		MFAType:   mfaType,
		Code:      code,
		ExpiresAt: time.Now().Add(5 * time.Minute), // Code expires in 5 minutes
	}

	mfa.mfaVerifications[userID] = verification
	return nil
}

// VerifyMFA verifies the provided MFA code for a user
func (mfa *MFAManager) VerifyMFA(userID, code string) (bool, error) {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	verification, exists := mfa.mfaVerifications[userID]
	if !exists {
		return false, fmt.Errorf("no MFA verification found for user ID %s", userID)
	}

	if time.Now().After(verification.ExpiresAt) {
		return false, fmt.Errorf("MFA verification code for user ID %s has expired", userID)
	}

	if verification.Code != code {
		return false, fmt.Errorf("invalid MFA verification code for user ID %s", userID)
	}

	delete(mfa.mfaVerifications, userID)
	return true, nil
}

// ListMFASetups lists all MFA setups for auditing purposes
func (mfa *MFAManager) ListMFASetups() []MFASetup {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	var setups []MFASetup
	for _, setup := range mfa.mfaSetups {
		setups = append(setups, setup)
	}

	return setups
}

// ListMFAVerifications lists all MFA verifications for auditing purposes
func (mfa *MFAManager) ListMFAVerifications() []MFAVerification {
	mfa.mutex.Lock()
	defer mfa.mutex.Unlock()

	var verifications []MFAVerification
	for _, verification := range mfa.mfaVerifications {
		verifications = append(verifications, verification)
	}

	return verifications
}
