package compliance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Constants
const (
	regulatoryReportFile   = "regulatory_reports.json"
	encryptionKeyEnvVar    = "REGULATORY_REPORT_ENCRYPTION_KEY"
	scryptN                = 1 << 15
	scryptR                = 8
	scryptP                = 1
	keyLength              = 32
	saltSize               = 16
)

// RegulatoryReport represents a regulatory report entry
type RegulatoryReport struct {
	Timestamp      time.Time `json:"timestamp"`
	ReportType     string    `json:"report_type"`
	Content        string    `json:"content"`
	Encrypted      bool      `json:"encrypted"`
	EncryptionSalt string    `json:"encryption_salt"`
}

// RegulatoryReporter handles the creation and management of regulatory reports
type RegulatoryReporter struct {
	encryptionKey []byte
}

// NewRegulatoryReporter initializes a new RegulatoryReporter
func NewRegulatoryReporter() (*RegulatoryReporter, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}
	return &RegulatoryReporter{encryptionKey: key}, nil
}

// GenerateReport generates a new regulatory report
func (r *RegulatoryReporter) GenerateReport(reportType string, content string) error {
	report := RegulatoryReport{
		Timestamp:  time.Now(),
		ReportType: reportType,
	}

	if r.encryptionKey != nil {
		salt := make([]byte, saltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return err
		}
		encryptedContent, err := encrypt(content, r.encryptionKey, salt)
		if err != nil {
			return err
		}
		report.Content = encryptedContent
		report.EncryptionSalt = base64.StdEncoding.EncodeToString(salt)
		report.Encrypted = true
	} else {
		report.Content = content
		report.Encrypted = false
	}

	return r.saveReport(report)
}

// saveReport saves a regulatory report to a file
func (r *RegulatoryReporter) saveReport(report RegulatoryReport) error {
	file, err := os.OpenFile(regulatoryReportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.Marshal(report)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	_, err = file.WriteString("\n")
	return err
}

// ReadReports reads and decrypts the regulatory reports
func (r *RegulatoryReporter) ReadReports() ([]RegulatoryReport, error) {
	file, err := os.Open(regulatoryReportFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reports []RegulatoryReport
	decoder := json.NewDecoder(file)
	for {
		var report RegulatoryReport
		if err := decoder.Decode(&report); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		if report.Encrypted && r.encryptionKey != nil {
			salt, err := base64.StdEncoding.DecodeString(report.EncryptionSalt)
			if err != nil {
				return nil, err
			}
			decryptedContent, err := decrypt(report.Content, r.encryptionKey, salt)
			if err != nil {
				return nil, err
			}
			report.Content = decryptedContent
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// ExportReportsCSV exports the reports to a CSV file
func (r *RegulatoryReporter) ExportReportsCSV(outputFile string) error {
	reports, err := r.ReadReports()
	if err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Timestamp", "ReportType", "Content"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, report := range reports {
		record := []string{report.Timestamp.Format(time.RFC3339), report.ReportType, report.Content}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// encrypt encrypts data using AES-GCM
func encrypt(data string, key []byte, salt []byte) (string, error) {
	derivedKey, err := scrypt.Key(key, salt, scryptN, scryptR, scryptP, keyLength)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// decrypt decrypts data using AES-GCM
func decrypt(encryptedData string, key []byte, salt []byte) (string, error) {
	derivedKey, err := scrypt.Key(key, salt, scryptN, scryptR, scryptP, keyLength)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derivedKey)
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

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// getEncryptionKey retrieves the encryption key from the environment or generates a new one
func getEncryptionKey() ([]byte, error) {
	key := os.Getenv(encryptionKeyEnvVar)
	if key == "" {
		return nil, errors.New("encryption key not set in environment")
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	derivedKey, err := scrypt.Key([]byte(key), salt, scryptN, scryptR, scryptP, keyLength)
	if err != nil {
		return nil, err
	}

	return derivedKey, nil
}
