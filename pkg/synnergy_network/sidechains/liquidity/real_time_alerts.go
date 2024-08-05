package liquidity

import (
	"fmt"
	"log"
	"net/smtp"
	"time"
	"encoding/json"
	"io/ioutil"
	"os"
)

// Alert represents a real-time alert message
type Alert struct {
	Timestamp   time.Time `json:"timestamp"`
	Message     string    `json:"message"`
	Severity    string    `json:"severity"`
}

// AlertManager manages the creation and sending of alerts
type AlertManager struct {
	EmailConfig EmailConfig
}

// EmailConfig holds the configuration for sending email alerts
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SenderEmail  string
	SenderPassword string
	RecipientEmail string
}

// NewAlertManager creates a new AlertManager
func NewAlertManager(config EmailConfig) *AlertManager {
	return &AlertManager{
		EmailConfig: config,
	}
}

// SendEmailAlert sends an email alert
func (am *AlertManager) SendEmailAlert(alert Alert) error {
	auth := smtp.PlainAuth("", am.EmailConfig.SenderEmail, am.EmailConfig.SenderPassword, am.EmailConfig.SMTPHost)

	to := []string{am.EmailConfig.RecipientEmail}
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", am.EmailConfig.RecipientEmail, alert.Severity, alert.Message))

	err := smtp.SendMail(am.EmailConfig.SMTPHost+":"+am.EmailConfig.SMTPPort, auth, am.EmailConfig.SenderEmail, to, msg)
	if err != nil {
		log.Printf("Failed to send email: %s", err)
		return err
	}

	log.Println("Email sent successfully")
	return nil
}

// GenerateAlert generates a new alert
func (am *AlertManager) GenerateAlert(message, severity string) Alert {
	return Alert{
		Timestamp: time.Now(),
		Message:   message,
		Severity:  severity,
	}
}

// LogAlert logs an alert to a file
func (am *AlertManager) LogAlert(alert Alert) error {
	file, err := os.OpenFile("alerts.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %s", err)
		return err
	}
	defer file.Close()

	logEntry := fmt.Sprintf("%s [%s]: %s\n", alert.Timestamp.Format(time.RFC3339), alert.Severity, alert.Message)
	if _, err := file.WriteString(logEntry); err != nil {
		log.Printf("Failed to write to log file: %s", err)
		return err
	}

	log.Println("Alert logged successfully")
	return nil
}

// SaveAlertToFile saves an alert to a JSON file
func (am *AlertManager) SaveAlertToFile(alert Alert, filename string) error {
	data, err := json.MarshalIndent(alert, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal alert: %s", err)
		return err
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		log.Printf("Failed to write alert to file: %s", err)
		return err
	}

	log.Println("Alert saved to file successfully")
	return nil
}

// MonitorEvents continuously monitors events and triggers alerts based on specific conditions
func (am *AlertManager) MonitorEvents(eventChannel chan string) {
	for {
		select {
		case event := <-eventChannel:
			alert := am.GenerateAlert(event, "HIGH")
			am.LogAlert(alert)
			am.SaveAlertToFile(alert, "latest_alert.json")
			am.SendEmailAlert(alert)
		}
	}
}
