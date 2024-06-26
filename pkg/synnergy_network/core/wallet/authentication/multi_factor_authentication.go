package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

// MultiFactorAuth provides methods for generating and verifying multi-factor authentication codes
type MultiFactorAuth struct {
	issuer string
}

// NewMultiFactorAuth creates a new instance of MultiFactorAuth
func NewMultiFactorAuth(issuer string) *MultiFactorAuth {
	return &MultiFactorAuth{
		issuer: issuer,
	}
}

// GenerateKey generates a new TOTP key for a user
func (mfa *MultiFactorAuth) GenerateKey(username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      mfa.issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// GenerateQRCode generates a QR code for the TOTP key
func (mfa *MultiFactorAuth) GenerateQRCode(w io.Writer, url string) error {
	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return err
	}
	img, err := key.Image(200, 200)
	if err != nil {
		return err
	}
	return png.Encode(w, img)
}

// VerifyCode verifies a TOTP code
func (mfa *MultiFactorAuth) VerifyCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// HashPassword hashes a password using Argon2
func HashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// VerifyPassword verifies a password against a given hash and salt
func VerifyPassword(password string, hash, salt []byte) bool {
	return string(hash) == string(argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32))
}

// GenerateSalt generates a new random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateRecoveryToken generates a recovery token
func GenerateRecoveryToken() (string, error) {
	token := make([]byte, 10)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(token), nil
}

// Middleware for HTTP handlers to enforce multi-factor authentication
func (mfa *MultiFactorAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Retrieve stored password hash and salt for the user (dummy data for illustration)
		storedHash := []byte{ /* fetch from secure storage */ }
		storedSalt := []byte{ /* fetch from secure storage */ }
		totpSecret := "" // fetch from secure storage

		if !VerifyPassword(password, storedHash, storedSalt) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Enforce TOTP verification
		code := r.URL.Query().Get("totp_code")
		if !mfa.VerifyCode(totpSecret, code) {
			http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Example usage of MultiFactorAuth and multi-factor authentication
func exampleUsage() {
	issuer := "Synthron"
	mfa := NewMultiFactorAuth(issuer)

	// Generate TOTP key for a user
	username := "user@example.com"
	secret, url, err := mfa.GenerateKey(username)
	if err != nil {
		fmt.Printf("Error generating TOTP key: %v\n", err)
		return
	}
	fmt.Printf("Generated TOTP secret: %s\n", secret)
	fmt.Printf("Generated TOTP URL: %s\n", url)

	// Generate a QR code for the TOTP key
	// Save QR code to file
	file, err := os.Create("totp_qr.png")
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	err = mfa.GenerateQRCode(file, url)
	if err != nil {
		fmt.Printf("Error generating QR code: %v\n", err)
		return
	}

	// Verify a TOTP code
	code := "123456" // This should be fetched from the user input in real application
	isValid := mfa.VerifyCode(secret, code)
	fmt.Printf("TOTP code is valid: %v\n", isValid)

	// Hash a password
	password := "securepassword"
	salt, err := GenerateSalt()
	if err != nil {
		fmt.Printf("Error generating salt: %v\n", err)
		return
	}
	hashedPassword := HashPassword(password, salt)
	fmt.Printf("Hashed password: %x\n", hashedPassword)

	// Verify the password
	isPasswordValid := VerifyPassword(password, hashedPassword, salt)
	fmt.Printf("Password is valid: %v\n", isPasswordValid)

	// Generate a recovery token
	recoveryToken, err := GenerateRecoveryToken()
	if err != nil {
		fmt.Printf("Error generating recovery token: %v\n", err)
		return
	}
	fmt.Printf("Generated recovery token: %s\n", recoveryToken)
}

func main() {
	exampleUsage()
}
