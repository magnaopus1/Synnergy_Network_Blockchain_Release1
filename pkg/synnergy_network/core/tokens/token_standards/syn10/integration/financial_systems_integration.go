package integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FinancialSystemsIntegration handles integration with traditional financial systems and ensures secure data exchange.
type FinancialSystemsIntegration struct {
	SystemName             string
	APIEndpoint            string
	APIToken               string
	EncryptedAPIToken      string
	EncryptionKey          string
	LastSync               time.Time
	ComplianceStatus       string
	IntegrationStartDate   time.Time
	ComplianceReports      []ComplianceReport
	DataFormatCompliance   string // e.g., ISO 20022, JSON
	SupportedCurrencies    []string
	SupportedTransactionTypes []string
}

// ComplianceReport represents a compliance report detailing interactions with financial systems.
type ComplianceReport struct {
	Date          time.Time
	Details       string
	Status        string
	ReportHash    string
}

// NewFinancialSystemsIntegration initializes a new instance with secure API token handling.
func NewFinancialSystemsIntegration(systemName, apiEndpoint, apiToken, encryptionKey string, supportedCurrencies, supportedTransactionTypes []string) (*FinancialSystemsIntegration, error) {
	encryptedToken, err := encryptToken(apiToken, encryptionKey)
	if err != nil {
		return nil, err
	}

	return &FinancialSystemsIntegration{
		SystemName:            systemName,
		APIEndpoint:           apiEndpoint,
		APIToken:              apiToken,
		EncryptedAPIToken:     encryptedToken,
		EncryptionKey:         encryptionKey,
		IntegrationStartDate:  time.Now(),
		ComplianceStatus:      "Pending",
		ComplianceReports:     []ComplianceReport{},
		DataFormatCompliance:  "ISO 20022",
		SupportedCurrencies:   supportedCurrencies,
		SupportedTransactionTypes: supportedTransactionTypes,
	}, nil
}

// encryptToken encrypts the API token using AES encryption with a secure key.
func encryptToken(token, key string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(token))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(token))

	return hex.EncodeToString(ciphertext), nil
}

// decryptToken decrypts the encrypted API token.
func decryptToken(encryptedToken, key string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedToken)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// createHash creates a SHA-256 hash for key encryption.
func createHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// UpdateComplianceStatus updates the compliance status of the integration.
func (fsi *FinancialSystemsIntegration) UpdateComplianceStatus(status, details string) {
	fsi.ComplianceStatus = status
	report := ComplianceReport{
		Date:       time.Now(),
		Details:    details,
		Status:     status,
		ReportHash: createHash(details),
	}
	fsi.ComplianceReports = append(fsi.ComplianceReports, report)
}

// GetAPIToken returns the decrypted API token for secure communications.
func (fsi *FinancialSystemsIntegration) GetAPIToken() (string, error) {
	return decryptToken(fsi.EncryptedAPIToken, fsi.EncryptionKey)
}

// LogSync records the time of the last data synchronization with the financial system.
func (fsi *FinancialSystemsIntegration) LogSync() {
	fsi.LastSync = time.Now()
}

// GetComplianceReports returns the compliance reports associated with the financial system integration.
func (fsi *FinancialSystemsIntegration) GetComplianceReports() []ComplianceReport {
	return fsi.ComplianceReports
}

// SyncData synchronizes data with the financial system, ensuring compatibility and compliance.
func (fsi *FinancialSystemsIntegration) SyncData() error {
	token, err := fsi.GetAPIToken()
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: time.Second * 30,
	}
	req, err := http.NewRequest("GET", fsi.APIEndpoint+"/sync", nil)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to sync data: %s", resp.Status)
	}

	fsi.LogSync()
	return nil
}
