package automated_reporting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"os"
	"time"

	"github.com/jordan-wright/email"
)

// Report contains the details of the report to be distributed
type Report struct {
	Title       string
	Content     string
	GeneratedAt time.Time
	Recipients  []string
}

// EncryptedReport contains the encrypted report details
type EncryptedReport struct {
	Title       string
	Content     []byte
	GeneratedAt time.Time
	Recipients  []string
}

// GenerateReport generates a new report
func GenerateReport(title, content string, recipients []string) *Report {
	return &Report{
		Title:       title,
		Content:     content,
		GeneratedAt: time.Now(),
		Recipients:  recipients,
	}
}

// EncryptReport encrypts the report content using AES encryption
func EncryptReport(report *Report, key []byte) (*EncryptedReport, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedContent := gcm.Seal(nonce, nonce, []byte(report.Content), nil)

	return &EncryptedReport{
		Title:       report.Title,
		Content:     encryptedContent,
		GeneratedAt: report.GeneratedAt,
		Recipients:  report.Recipients,
	}, nil
}

// DecryptReport decrypts the encrypted report content
func DecryptReport(encryptedReport *EncryptedReport, key []byte) (*Report, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedReport.Content) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encryptedReport.Content[:nonceSize], encryptedReport.Content[nonceSize:]
	decryptedContent, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return &Report{
		Title:       encryptedReport.Title,
		Content:     string(decryptedContent),
		GeneratedAt: encryptedReport.GeneratedAt,
		Recipients:  encryptedReport.Recipients,
	}, nil
}

// SaveReport saves the report to a file
func SaveReport(report *Report, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(report)
}

// LoadReport loads the report from a file
func LoadReport(filename string) (*Report, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var report Report
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&report); err != nil {
		return nil, err
	}

	return &report, nil
}

// DistributeReport distributes the report to the specified recipients via email
func DistributeReport(report *Report, smtpHost, smtpPort, smtpUser, smtpPass string) error {
	e := email.NewEmail()
	e.From = fmt.Sprintf("Report Distribution <%s>", smtpUser)
	e.To = report.Recipients
	e.Subject = report.Title
	e.Text = []byte(report.Content)

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	return e.Send(fmt.Sprintf("%s:%s", smtpHost, smtpPort), auth)
}

// ArchiveReport archives the report by saving it to a specified directory
func ArchiveReport(report *Report, archiveDir string) error {
	if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
		if err := os.MkdirAll(archiveDir, 0755); err != nil {
			return err
		}
	}

	filename := fmt.Sprintf("%s/%s_%d.json", archiveDir, report.Title, report.GeneratedAt.Unix())
	return SaveReport(report, filename)
}
