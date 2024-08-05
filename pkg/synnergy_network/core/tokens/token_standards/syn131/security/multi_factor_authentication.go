package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
)

type MFA struct {
	users           map[string]UserMFA
	eventDispatcher events.EventDispatcher
}

type UserMFA struct {
	UserID          string
	Email           string
	Secret          string
	RecoveryCodes   []string
	LastAuthAttempt time.Time
}

const (
	recoveryCodeLength = 16
	recoveryCodeCount  = 10
	smtpHost           = "smtp.example.com"
	smtpPort           = "587"
	smtpUsername       = "your-email@example.com"
	smtpPassword       = "your-email-password"
)

func NewMFA(eventDispatcher events.EventDispatcher) *MFA {
	return &MFA{
		users:           make(map[string]UserMFA),
		eventDispatcher: eventDispatcher,
	}
}

func (mfa *MFA) EnableMFA(userID, email string) (string, error) {
	secret, err := generateSecret()
	if err != nil {
		return "", err
	}

	userMFA := UserMFA{
		UserID:        userID,
		Email:         email,
		Secret:        secret,
		RecoveryCodes: generateRecoveryCodes(),
	}

	mfa.users[userID] = userMFA

	event := events.Event{
		Type:    events.MFAEnabled,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := mfa.eventDispatcher.Dispatch(event); err != nil {
		return "", err
	}

	return secret, nil
}

func (mfa *MFA) Authenticate(userID, token string) error {
	userMFA, exists := mfa.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	valid := totp.Validate(token, userMFA.Secret)
	if !valid {
		return errors.New("invalid token")
	}

	userMFA.LastAuthAttempt = time.Now()
	mfa.users[userID] = userMFA

	event := events.Event{
		Type:    events.MFAAuthenticated,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := mfa.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

func (mfa *MFA) DisableMFA(userID string) error {
	_, exists := mfa.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	delete(mfa.users, userID)

	event := events.Event{
		Type:    events.MFADisabled,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := mfa.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

func (mfa *MFA) ValidateRecoveryCode(userID, recoveryCode string) error {
	userMFA, exists := mfa.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	for i, code := range userMFA.RecoveryCodes {
		if code == recoveryCode {
			userMFA.RecoveryCodes = append(userMFA.RecoveryCodes[:i], userMFA.RecoveryCodes[i+1:]...)
			mfa.users[userID] = userMFA

			event := events.Event{
				Type:    events.MFARecoveryCodeUsed,
				Payload: map[string]interface{}{"userID": userID},
			}
			if err := mfa.eventDispatcher.Dispatch(event); err != nil {
				return err
			}

			return nil
		}
	}

	return errors.New("invalid recovery code")
}

func generateSecret() (string, error) {
	secret := make([]byte, 10)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func generateRecoveryCodes() []string {
	codes := make([]string, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		codes[i] = generateRecoveryCode()
	}
	return codes
}

func generateRecoveryCode() string {
	code := make([]byte, recoveryCodeLength)
	if _, err := rand.Read(code); err != nil {
		return ""
	}

	hash := sha256.New()
	hash.Write(code)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func sendEmail(recipient, subject, body string) error {
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)

	msg := []byte("To: " + recipient + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body + "\r\n")

	return smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUsername, []string{recipient}, msg)
}

func (mfa *MFA) SendMFACodeByEmail(userID, email string) error {
	userMFA, exists := mfa.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	token, err := totp.GenerateCode(userMFA.Secret, time.Now())
	if err != nil {
		return err
	}

	subject := "Your MFA Code"
	body := fmt.Sprintf("Your MFA code is: %s", token)

	return sendEmail(email, subject, body)
}
