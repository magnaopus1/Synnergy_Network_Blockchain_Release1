package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/smtp"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFASecret represents a multi-factor authentication secret
type MFASecret struct {
	Secret     string
	BackupCodes []string
	Issuer     string
	Account    string
}

// MFAService handles multi-factor authentication operations
type MFAService struct {
	mu         sync.Mutex
	Secrets    map[string]MFASecret
	EmailServer *EmailServer
}

// EmailServer configuration for sending OTPs via email
type EmailServer struct {
	Host     string
	Port     int
	Username string
	Password string
}

// NewMFAService creates a new MFAService instance
func NewMFAService(emailServer *EmailServer) *MFAService {
	return &MFAService{
		Secrets:     make(map[string]MFASecret),
		EmailServer: emailServer,
	}
}

// GenerateSecret generates a new MFA secret for a user
func (s *MFAService) GenerateSecret(userID, issuer, account string) (MFASecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return MFASecret{}, err
	}

	backupCodes, err := generateBackupCodes(10)
	if err != nil {
		return MFASecret{}, err
	}

	secret := MFASecret{
		Secret:     key.Secret(),
		BackupCodes: backupCodes,
		Issuer:     issuer,
		Account:    account,
	}

	s.Secrets[userID] = secret
	return secret, nil
}

// ValidateTOTP validates the provided TOTP code for a user
func (s *MFAService) ValidateTOTP(userID, code string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	secret, exists := s.Secrets[userID]
	if !exists {
		return false, errors.New("secret not found")
	}

	valid := totp.Validate(code, secret.Secret)
	return valid, nil
}

// GenerateEmailOTP generates and sends an OTP to the user's email
func (s *MFAService) GenerateEmailOTP(userID, email string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	otpCode, err := generateOTPCode()
	if err != nil {
		return "", err
	}

	if err := s.sendEmail(email, otpCode); err != nil {
		return "", err
	}

	return otpCode, nil
}

// ValidateEmailOTP validates the provided email OTP for a user
func (s *MFAService) ValidateEmailOTP(userID, code string) (bool, error) {
	// This should be implemented with a more secure and persistent storage mechanism
	return false, errors.New("not implemented")
}

// GenerateBackupCodes generates a set of backup codes for MFA
func generateBackupCodes(n int) ([]string, error) {
	var codes []string
	for i := 0; i < n; i++ {
		code, err := generateOTPCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// GenerateOTPCode generates a random OTP code
func generateOTPCode() (string, error) {
	otpBytes := make([]byte, 6)
	_, err := rand.Read(otpBytes)
	if err != nil {
		return "", err
	}

	code := base32.StdEncoding.EncodeToString(otpBytes)
	return code[:6], nil
}

// SendEmail sends an email with the OTP code
func (s *MFAService) sendEmail(to, otpCode string) error {
	from := s.EmailServer.Username
	password := s.EmailServer.Password

	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: Your OTP Code\n\nYour OTP code is: %s", from, to, otpCode)

	auth := smtp.PlainAuth("", from, password, s.EmailServer.Host)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", s.EmailServer.Host, s.EmailServer.Port), auth, from, []string{to}, []byte(msg))
	if err != nil {
		return err
	}

	return nil
}

// HashPassword hashes the password using SHA-256
func HashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// ValidateBackupCode validates a backup code for MFA
func (s *MFAService) ValidateBackupCode(userID, code string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	secret, exists := s.Secrets[userID]
	if !exists {
		return false, errors.New("secret not found")
	}

	for i, backupCode := range secret.BackupCodes {
		if backupCode == code {
			// Invalidate the used backup code
			secret.BackupCodes[i] = ""
			s.Secrets[userID] = secret
			return true, nil
		}
	}

	return false, errors.New("invalid backup code")
}

// ToJSON serializes the MFA secret to JSON
func (m MFASecret) ToJSON() (string, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes the JSON string to an MFA secret
func (m *MFASecret) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), m)
}
