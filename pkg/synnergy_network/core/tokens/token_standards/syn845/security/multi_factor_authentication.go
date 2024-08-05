package security

import (
	"encoding/base32"
	"errors"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFASecret holds the secret for a user for MFA
type MFASecret struct {
	UserID string
	Secret string
}

// MFAStore holds the store for MFA secrets
var MFAStore = make(map[string]MFASecret)

// GenerateMFASecret generates a new MFA secret for a user
func GenerateMFASecret(userID string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SYN845",
		AccountName: userID,
	})
	if err != nil {
		return "", err
	}

	secret := key.Secret()
	MFAStore[userID] = MFASecret{UserID: userID, Secret: secret}

	return secret, nil
}

// ValidateMFAToken validates the provided TOTP token for the user
func ValidateMFAToken(userID, token string) (bool, error) {
	mfaSecret, exists := MFAStore[userID]
	if !exists {
		return false, errors.New("MFA secret not found for user")
	}

	valid := totp.Validate(token, mfaSecret.Secret)
	return valid, nil
}

// GetMFAQRCode generates a QR code URL for setting up MFA with an authenticator app
func GetMFAQRCode(userID string) (string, error) {
	mfaSecret, exists := MFAStore[userID]
	if !exists {
		return "", errors.New("MFA secret not found for user")
	}

	key, err := otp.NewKeyFromURL("otpauth://totp/SYN845:" + userID + "?secret=" + mfaSecret.Secret + "&issuer=SYN845")
	if err != nil {
		return "", err
	}

	// Generate a base32-encoded secret for the user
	secretBase32 := base32.StdEncoding.EncodeToString([]byte(mfaSecret.Secret))

	return key.String(), nil
}

// EnforceMFA ensures the user provides a valid MFA token before proceeding
func EnforceMFA(userID, token string) error {
	valid, err := ValidateMFAToken(userID, token)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid MFA token")
	}
	return nil
}
