package authentication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/argon2"
	"github.com/skip2/go-qrcode"
)

// BiometricAuthMiddleware handles biometric authentication and JWT generation for HTTP requests.
type BiometricAuthMiddleware struct {
	jwtKey []byte
}

// NewBiometricAuthMiddleware creates a new instance of BiometricAuthMiddleware.
func NewBiometricAuthMiddleware(jwtKey string) *BiometricAuthMiddleware {
	return &BiometricAuthMiddleware{
		jwtKey: []byte(jwtKey),
	}
}

// GenerateJWT generates a JWT for a given user ID.
func (bam *BiometricAuthMiddleware) GenerateJWT(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(bam.jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ParseJWT parses and validates a JWT, returning the user ID if valid.
func (bam *BiometricAuthMiddleware) ParseJWT(tokenString string) (string, error) {
	claims := &jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return bam.jwtKey, nil
	})

	if err != nil || !token.Valid {
		return "", err
	}

	userID, ok := (*claims)["userID"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return userID, nil
}

// Middleware is the actual middleware function to be used in HTTP handlers.
func (bam *BiometricAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		authToken := strings.TrimPrefix(authHeader, "Bearer ")
		userID, err := bam.ParseJWT(authToken)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GenerateQRCode generates a QR code for the provided data.
func GenerateQRCode(data string) ([]byte, error) {
	qrCode, err := qrcode.Encode(data, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return qrCode, nil
}

// HashPassword hashes a password using Argon2.
func HashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// VerifyPassword verifies a password against a given hash and salt.
func VerifyPassword(password string, hash, salt []byte) bool {
	return string(hash) == string(argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32))
}

// GenerateBiometricHash generates a hash for biometric data.
func GenerateBiometricHash(biometricData []byte) string {
	hash := sha256.Sum256(biometricData)
	return hex.EncodeToString(hash[:])
}

// Example usage of the BiometricAuthMiddleware and biometric authentication
func exampleUsage() {
	jwtKey := "your-256-bit-secret"
	authMiddleware := NewBiometricAuthMiddleware(jwtKey)

	// Generating a JWT for a user
	userID := "123456"
	token, err := authMiddleware.GenerateJWT(userID)
	if err != nil {
		fmt.Printf("Error generating JWT: %v\n", err)
		return
	}
	fmt.Printf("Generated JWT: %s\n", token)

	// Parsing and validating the JWT
	parsedUserID, err := authMiddleware.ParseJWT(token)
	if err != nil {
		fmt.Printf("Error parsing JWT: %v\n", err)
		return
	}
	fmt.Printf("Parsed user ID: %s\n", parsedUserID)

	// Hashing a password
	password := "supersecurepassword"
	salt := []byte("somesalt")
	hash := HashPassword(password, salt)
	fmt.Printf("Password hash: %x\n", hash)

	// Verifying a password
	isValid := VerifyPassword(password, hash, salt)
	fmt.Printf("Password is valid: %v\n", isValid)

	// Generating a biometric hash
	biometricData := []byte("user-fingerprint-data")
	biometricHash := GenerateBiometricHash(biometricData)
	fmt.Printf("Biometric hash: %s\n", biometricHash)

	// Generating a QR code
	qrCodeData, err := GenerateQRCode("http://example.com/authenticate")
	if err != nil {
		fmt.Printf("Error generating QR code: %v\n", err)
		return
	}
	fmt.Printf("Generated QR code: %x\n", qrCodeData)
}

func main() {
	exampleUsage()
}
