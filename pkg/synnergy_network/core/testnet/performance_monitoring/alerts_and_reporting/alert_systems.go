// Package alerts_and_reporting provides alerting and reporting tools for the Synnergy Network.
package alerts_and_reporting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/smtp"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
)

// Alert represents a system alert.
type Alert struct {
	ID        string    `json:"id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Handled   bool      `json:"handled"`
}

// AlertSystem manages alerts within the network.
type AlertSystem struct {
	Alerts       []Alert
	EncryptionKey string
}

// NewAlertSystem creates a new AlertSystem.
func NewAlertSystem(encryptionKey string) *AlertSystem {
	return &AlertSystem{
		Alerts:       []Alert{},
		EncryptionKey: encryptionKey,
	}
}

// GenerateEncryptionKey generates a secure encryption key.
func GenerateEncryptionKey() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.Key([]byte("synnergy_alert_system"), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(key)
}

// Encrypt encrypts the given data using AES encryption with the provided key.
func Encrypt(key, text string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(text), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given data using AES decryption with the provided key.
func Decrypt(key, cryptoText string) (string, error) {
	data, err := hex.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// AddAlert adds a new alert to the system.
func (as *AlertSystem) AddAlert(level, message string) {
	alert := Alert{
		ID:        generateAlertID(),
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Handled:   false,
	}
	as.Alerts = append(as.Alerts, alert)
}

// generateAlertID generates a unique alert ID.
func generateAlertID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// HandleAlert marks an alert as handled.
func (as *AlertSystem) HandleAlert(alertID string) error {
	for i, alert := range as.Alerts {
		if alert.ID == alertID {
			as.Alerts[i].Handled = true
			return nil
		}
	}
	return errors.New("alert not found")
}

// SendEmail sends an email notification for an alert.
func (as *AlertSystem) SendEmail(alert Alert, recipient string) error {
	from := "synnergy.alerts@example.com"
	password := "your-email-password"

	smtpHost := "smtp.example.com"
	smtpPort := "587"

	message := []byte(fmt.Sprintf("To: %s\r\nSubject: Synnergy Network Alert\r\n\r\n%s", recipient, alert.Message))

	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{recipient}, message)
	if err != nil {
		return err
	}
	return nil
}

// SaveAlerts saves the alerts to a file.
func (as *AlertSystem) SaveAlerts(filePath string) error {
	data, err := json.Marshal(as.Alerts)
	if err != nil {
		return err
	}

	encryptedData, err := Encrypt(as.EncryptionKey, string(data))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, []byte(encryptedData), 0644)
}

// LoadAlerts loads the alerts from a file.
func (as *AlertSystem) LoadAlerts(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	decryptedData, err := Decrypt(as.EncryptionKey, string(data))
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(decryptedData), &as.Alerts)
}

// MonitorAlerts monitors alerts and sends notifications based on alert levels.
func (as *AlertSystem) MonitorAlerts(recipient string) {
	for {
		for _, alert := range as.Alerts {
			if !alert.Handled && alert.Level == "critical" {
				as.SendEmail(alert, recipient)
				as.HandleAlert(alert.ID)
			}
		}
		time.Sleep(1 * time.Minute)
	}
}

// Example usage of the alert system.
func main() {
	encryptionKey := GenerateEncryptionKey()
	alertSystem := NewAlertSystem(encryptionKey)

	alertSystem.AddAlert("critical", "Node 1 is down!")
	alertSystem.AddAlert("warning", "High memory usage on Node 2")

	err := alertSystem.SaveAlerts("alerts.dat")
	if err != nil {
		fmt.Printf("Error saving alerts: %v\n", err)
	}

	err = alertSystem.LoadAlerts("alerts.dat")
	if err != nil {
		fmt.Printf("Error loading alerts: %v\n", err)
	}

	go alertSystem.MonitorAlerts("admin@example.com")

	select {} // Keep the program running
}
