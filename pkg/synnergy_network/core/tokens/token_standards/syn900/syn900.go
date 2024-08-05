package syn900

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"net/http"
	"time"
)

// Syn900Token represents a SYN900 identity token
type Syn900Token struct {
	TokenID             string                 `json:"token_id"`
	Owner               string                 `json:"owner"`
	IdentityDetails     IdentityMetadata       `json:"identity_details"`
	VerificationLog     []VerificationRecord   `json:"verification_log"`
	AuditTrail          []AuditRecord          `json:"audit_trail"`
	ComplianceRecords   []ComplianceRecord     `json:"compliance_records"`
	RegisteredWallets   []string               `json:"registered_wallets"`
	DrivingLicenseHash  string                 `json:"driving_license_hash"`
	EncryptedPassNumber string                 `json:"encrypted_pass_number"`
}

// IdentityMetadata holds detailed personal information
type IdentityMetadata struct {
	FullName        string `json:"full_name"`
	DateOfBirth     string `json:"date_of_birth"`
	Nationality     string `json:"nationality"`
	PhotographHash  string `json:"photograph_hash"`
	PhysicalAddress string `json:"physical_address"`
}

// VerificationRecord keeps track of verification events
type VerificationRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	Method    string    `json:"method"`
}

// AuditRecord represents an audit log entry
type AuditRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
}

// ComplianceRecord documents compliance with regulations
type ComplianceRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Detail    string    `json:"detail"`
}

// EncryptData encrypts data using AES encryption with Argon2 key derivation
func EncryptData(plainText, password string) (string, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptData decrypts AES encrypted data with Argon2 key derivation
func DecryptData(cipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// HashData hashes data using SHA-256
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// AddVerificationLog adds a verification event to the token
func (t *Syn900Token) AddVerificationLog(status, method string) {
	record := VerificationRecord{
		Timestamp: time.Now(),
		Status:    status,
		Method:    method,
	}
	t.VerificationLog = append(t.VerificationLog, record)
}

// AddAuditLog adds an audit event to the token
func (t *Syn900Token) AddAuditLog(event string) {
	record := AuditRecord{
		Timestamp: time.Now(),
		Event:     event,
	}
	t.AuditTrail = append(t.AuditTrail, record)
}

// AddComplianceRecord adds a compliance record to the token
func (t *Syn900Token) AddComplianceRecord(detail string) {
	record := ComplianceRecord{
		Timestamp: time.Now(),
		Detail:    detail,
	}
	t.ComplianceRecords = append(t.ComplianceRecords, record)
}

// VerifyIdentity performs identity verification using an external API
func (t *Syn900Token) VerifyIdentity(method, apiUrl string, verificationFunc func(string) bool) error {
	resp, err := http.Get(apiUrl)
	if err != nil {
		t.AddVerificationLog("failed", method)
		return err
	}
	defer resp.Body.Close()

	if verificationFunc(apiUrl) {
		t.AddVerificationLog("verified", method)
		return nil
	}
	t.AddVerificationLog("failed", method)
	return errors.New("verification failed")
}

// AddWalletAddress registers a new wallet address
func (t *Syn900Token) AddWalletAddress(address string) {
	t.RegisteredWallets = append(t.RegisteredWallets, address)
}

// TransferToken creates instances of the token in multiple addresses
func (t *Syn900Token) TransferToken(addresses []string) []*Syn900Token {
	var tokens []*Syn900Token
	for _, address := range addresses {
		newToken := *t
		newToken.Owner = address
		tokens = append(tokens, &newToken)
	}
	return tokens
}

// SaveToken serializes the token to JSON
func (t *Syn900Token) SaveToken() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadToken deserializes the token from JSON
func LoadToken(data string) (*Syn900Token, error) {
	var token Syn900Token
	err := json.Unmarshal([]byte(data), &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// ZeroKnowledgeProof demonstrates zero-knowledge proof of identity without revealing details
func (t *Syn900Token) ZeroKnowledgeProof(attribute string, proofFunc func(IdentityMetadata, string) bool) bool {
	return proofFunc(t.IdentityDetails, attribute)
}

// Example zero-knowledge proof function
func exampleZKPFunction(details IdentityMetadata, attribute string) bool {
	hash := sha256.Sum256([]byte(attribute))
	return sha512.Sum512_256([]byte(details.FullName)) == hash
}

func main() {
	// Example of creating and using a Syn900Token
	identity := IdentityMetadata{
		FullName:        "John Doe",
		DateOfBirth:     "1990-01-01",
		Nationality:     "US",
		PhotographHash:  "examplehash",
		PhysicalAddress: "1234 Blockchain Ave",
	}

	token := Syn900Token{
		TokenID:            "unique-token-id",
		Owner:              "john.doe@example.com",
		IdentityDetails:    identity,
		DrivingLicenseHash: HashData("D1234567"),
	}

	password := "strongpassword"
	encryptedPassNumber, err := EncryptData("P1234567", password)
	if err != nil {
		fmt.Println("Error encrypting passport number:", err)
		return
	}
	token.EncryptedPassNumber = encryptedPassNumber

	err = token.VerifyIdentity("api_method", "https://example.com/verify", func(apiUrl string) bool {
		// Simulate API verification
		return true
	})
	if err != nil {
		fmt.Println("Verification failed:", err)
	}

	token.AddWalletAddress("0x12345")
	token.AddWalletAddress("0x67890")

	tokens := token.TransferToken([]string{"0xabcde", "0xfghij"})
	for _, t := range tokens {
		fmt.Println("Token owner:", t.Owner)
	}

	// Save and load token example
	savedToken, err := token.SaveToken()
	if err != nil {
		fmt.Println("Error saving token:", err)
		return
	}

	loadedToken, err := LoadToken(savedToken)
	if err != nil {
		fmt.Println("Error loading token:", err)
		return
	}

	fmt.Println("Loaded Token:", loadedToken)
}
