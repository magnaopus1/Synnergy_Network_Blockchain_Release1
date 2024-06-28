package authentication

import (
	"errors"
	"net/http"
	"github.com/synnergy-network/blockchain/crypto"
	"github.com/synnergy-network/wallet/security"
)

// MultiFactorAuthenticator manages the multi-factor authentication process.
type MultiFactorAuthenticator struct {
	userDatabase UserDatabase
	totpProvider TOTPProvider
	smsProvider  SMSProvider
}

// UserDatabase provides access to user data storage.
type UserDatabase interface {
	GetUser(username string) (*User, error)
	SaveUser(user *User) error
}

// TOTPProvider defines an interface for TOTP (Time-based One-Time Password).
type TOTPProvider interface {
	GenerateSecret() string
	ValidateTOTP(secret, token string) bool
}

// SMSProvider sends SMS messages for SMS-based authentication.
type SMSProvider interface {
	SendSMS(phoneNumber, message string) error
}

// User holds data related to a user account.
type User struct {
	Username      string
	PasswordHash  string
	TOTPSecret    string
	PhoneNumber   string
	Email         string
	IsVerified    bool
}

// NewMultiFactorAuthenticator creates a new instance of MultiFactorAuthenticator.
func NewMultiFactorAuthenticator(db UserDatabase, totp TOTPProvider, sms SMSProvider) *MultiFactorAuthenticator {
	return &MultiFactorAuthenticator{
		userDatabase: db,
		totpProvider: totp,
		smsProvider:  sms,
	}
}

// RegisterNewUser handles registration of new users including TOTP setup.
func (mfa *MultiFactorAuthenticator) RegisterNewUser(username, password, phoneNumber string) error {
	passwordHash := crypto.HashPassword(password)
	totpSecret := mfa.totpProvider.GenerateSecret()

	user := &User{
		Username:     username,
		PasswordHash: passwordHash,
		TOTPSecret:   totpSecret,
		PhoneNumber:  phoneNumber,
		Email:        "",
		IsVerified:   false,
	}

	if err := mfa.userDatabase.SaveUser(user); err != nil {
		return err
	}

	// Send SMS to verify phone number
	verificationCode := "123456" // This should be generated dynamically
	return mfa.smsProvider.SendSMS(phoneNumber, "Your verification code is: "+verificationCode)
}

// VerifyTOTP checks the provided TOTP against the stored secret.
func (mfa *MultiFactorAuthenticator) VerifyTOTP(username, token string) error {
	user, err := mfa.userDatabase.GetUser(username)
	if err != nil {
		return err
	}

	if mfa.totpProvider.ValidateTOTP(user.TOTPSecret, token) {
		user.IsVerified = true
		return mfa.userDatabase.SaveUser(user)
	}

	return errors.New("invalid TOTP token")
}

// Login performs multi-factor authentication using password and TOTP.
func (mfa *MultiFactorAuthenticator) Login(username, password, token string) error {
	user, err := mfa.userDatabase.GetUser(username)
	if err != nil {
		return err
	}

	if !crypto.CompareHashAndPassword(user.PasswordHash, password) {
		return errors.New("invalid username or password")
	}

	if !mfa.totpProvider.ValidateTOTP(user.TOTPSecret, token) {
		return errors.New("invalid TOTP token")
	}

	if !user.IsVerified {
		return errors.New("user not verified")
	}

	return nil
}
