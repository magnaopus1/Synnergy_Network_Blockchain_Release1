package alerting_and_notifications

import (
    "encoding/json"
    "log"
    "net/smtp"
    "time"
    "github.com/pkg/errors"
    "github.com/synnergy_network/core/security"
    "github.com/synnergy_network/core/encryption"
)

// AlertLevel represents the severity of the alert
type AlertLevel int

const (
    INFO AlertLevel = iota
    WARNING
    CRITICAL
)

// Alert represents a real-time alert structure
type Alert struct {
    ID        string     `json:"id"`
    Timestamp time.Time  `json:"timestamp"`
    Level     AlertLevel `json:"level"`
    Message   string     `json:"message"`
}

// NotificationChannel represents the interface for sending notifications
type NotificationChannel interface {
    Send(alert Alert) error
}

// EmailChannel represents an email notification channel
type EmailChannel struct {
    SMTPServer   string
    SMTPPort     int
    Username     string
    Password     string
    FromAddress  string
    ToAddress    string
}

// Send sends an alert via email
func (ec *EmailChannel) Send(alert Alert) error {
    auth := smtp.PlainAuth("", ec.Username, ec.Password, ec.SMTPServer)
    subject := "Alert: " + alert.Level.String()
    body := "Time: " + alert.Timestamp.String() + "\n" + "Message: " + alert.Message
    msg := []byte("To: " + ec.ToAddress + "\r\n" +
        "Subject: " + subject + "\r\n" +
        "\r\n" +
        body + "\r\n")

    err := smtp.SendMail(ec.SMTPServer+":"+string(ec.SMTPPort), auth, ec.FromAddress, []string{ec.ToAddress}, msg)
    if err != nil {
        return errors.Wrap(err, "failed to send email")
    }
    return nil
}

// WebhookChannel represents a webhook notification channel
type WebhookChannel struct {
    URL string
}

// Send sends an alert via a webhook
func (wc *WebhookChannel) Send(alert Alert) error {
    jsonData, err := json.Marshal(alert)
    if err != nil {
        return errors.Wrap(err, "failed to marshal alert to JSON")
    }

    _, err = http.Post(wc.URL, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        return errors.Wrap(err, "failed to send webhook")
    }
    return nil
}

// AlertManager manages the sending of alerts to different channels
type AlertManager struct {
    Channels []NotificationChannel
}

// NewAlertManager creates a new AlertManager
func NewAlertManager() *AlertManager {
    return &AlertManager{
        Channels: make([]NotificationChannel, 0),
    }
}

// RegisterChannel registers a new notification channel
func (am *AlertManager) RegisterChannel(channel NotificationChannel) {
    am.Channels = append(am.Channels, channel)
}

// SendAlert sends an alert to all registered channels
func (am *AlertManager) SendAlert(alert Alert) {
    for _, channel := range am.Channels {
        err := channel.Send(alert)
        if err != nil {
            log.Printf("failed to send alert: %v", err)
        }
    }
}

// AlertLevel Stringer
func (level AlertLevel) String() string {
    switch level {
    case INFO:
        return "INFO"
    case WARNING:
        return "WARNING"
    case CRITICAL:
        return "CRITICAL"
    default:
        return "UNKNOWN"
    }
}

// Function to generate a new alert ID (UUID)
func generateAlertID() string {
    // Generate a new UUID
    return encryption.GenerateUUID()
}

// Function to create a new alert
func NewAlert(level AlertLevel, message string) Alert {
    return Alert{
        ID:        generateAlertID(),
        Timestamp: time.Now(),
        Level:     level,
        Message:   message,
    }
}

// Initialize and test the AlertManager with channels
func InitAlertSystem() {
    am := NewAlertManager()

    // Set up email channel (example details, should be replaced with actual)
    emailChannel := &EmailChannel{
        SMTPServer:  "smtp.example.com",
        SMTPPort:    587,
        Username:    "user@example.com",
        Password:    "password",
        FromAddress: "alert@example.com",
        ToAddress:   "admin@example.com",
    }

    // Set up webhook channel (example URL, should be replaced with actual)
    webhookChannel := &WebhookChannel{
        URL: "https://example.com/webhook",
    }

    am.RegisterChannel(emailChannel)
    am.RegisterChannel(webhookChannel)

    // Example of sending an alert
    alert := NewAlert(CRITICAL, "Test alert: something went critically wrong!")
    am.SendAlert(alert)
}
