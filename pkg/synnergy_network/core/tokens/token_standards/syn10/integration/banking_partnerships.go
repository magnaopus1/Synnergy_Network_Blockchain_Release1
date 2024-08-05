package integration

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "time"
)

// BankingPartnerships manages the integration of the SYN10 Token Standard with traditional banking systems.
type BankingPartnerships struct {
    BankName           string
    APIEndpoint        string
    APIToken           string
    EncryptedAPIToken  string
    EncryptionKey      string
    LastInteraction    time.Time
    ComplianceStatus   string
    PartneredSince     time.Time
    ComplianceReports  []ComplianceReport
}

// ComplianceReport represents a report of compliance interactions and status with banking partners.
type ComplianceReport struct {
    Date          time.Time
    Details       string
    Status        string
    ReportHash    string
}

// NewBankingPartnerships creates a new BankingPartnerships instance with secure API token handling.
func NewBankingPartnerships(bankName, apiEndpoint, apiToken, encryptionKey string) (*BankingPartnerships, error) {
    encryptedToken, err := encryptToken(apiToken, encryptionKey)
    if err != nil {
        return nil, err
    }

    return &BankingPartnerships{
        BankName:          bankName,
        APIEndpoint:       apiEndpoint,
        APIToken:          apiToken,
        EncryptedAPIToken: encryptedToken,
        EncryptionKey:     encryptionKey,
        PartneredSince:    time.Now(),
        ComplianceStatus:  "Pending",
        ComplianceReports: []ComplianceReport{},
    }, nil
}

// encryptToken encrypts the API token using AES encryption.
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

// createHash creates a SHA-256 hash of the key for encryption.
func createHash(key string) string {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}

// UpdateComplianceStatus updates the compliance status of the banking partnership.
func (bp *BankingPartnerships) UpdateComplianceStatus(status, details string) {
    bp.ComplianceStatus = status
    report := ComplianceReport{
        Date:       time.Now(),
        Details:    details,
        Status:     status,
        ReportHash: createHash(details),
    }
    bp.ComplianceReports = append(bp.ComplianceReports, report)
}

// GetAPIToken returns the decrypted API token for secure communications.
func (bp *BankingPartnerships) GetAPIToken() (string, error) {
    return decryptToken(bp.EncryptedAPIToken, bp.EncryptionKey)
}

// LogInteraction records the time of the last interaction with the banking partner.
func (bp *BankingPartnerships) LogInteraction() {
    bp.LastInteraction = time.Now()
}

// GetComplianceReports returns the compliance reports associated with the banking partnership.
func (bp *BankingPartnerships) GetComplianceReports() []ComplianceReport {
    return bp.ComplianceReports
}
