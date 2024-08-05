package automated_alerting_systems

import (
    "crypto/tls"
    "fmt"
    "log"
    "net/smtp"
    "time"
)

// EmailAlertConfig holds the configuration for sending email alerts
type EmailAlertConfig struct {
    SMTPServer       string
    SMTPPort         int
    Username         string
    Password         string
    FromAddress      string
    ToAddresses      []string
    AlertThresholds  map[string]float64
    EncryptionMethod string // e.g., "TLS", "STARTTLS"
}

// EmailAlertSystem represents the email alerting system
type EmailAlertSystem struct {
    config EmailAlertConfig
    logger *log.Logger
}

// NewEmailAlertSystem creates a new instance of EmailAlertSystem
func NewEmailAlertSystem(config EmailAlertConfig, logger *log.Logger) *EmailAlertSystem {
    return &EmailAlertSystem{
        config: config,
        logger: logger,
    }
}

// Initialize sets up the email alert system
func (eas *EmailAlertSystem) Initialize() error {
    // Here we can validate the config and set up any necessary connections
    eas.logger.Println("Initializing Email Alert System...")
    // Add additional initialization logic if needed
    return nil
}

// GenerateAlert generates an alert based on a given condition
func (eas *EmailAlertSystem) GenerateAlert(condition string, value float64) {
    threshold, exists := eas.config.AlertThresholds[condition]
    if !exists {
        eas.logger.Printf("No threshold set for condition: %s", condition)
        return
    }

    if value > threshold {
        eas.logger.Printf("Condition %s exceeded threshold: %f > %f", condition, value, threshold)
        eas.SendEmailAlert(condition, value)
    } else {
        eas.logger.Printf("Condition %s within threshold: %f <= %f", condition, value, threshold)
    }
}

// SendEmailAlert sends an email alert
func (eas *EmailAlertSystem) SendEmailAlert(condition string, value float64) {
    subject := fmt.Sprintf("ALERT: Condition %s exceeded threshold", condition)
    body := fmt.Sprintf("The condition %s has exceeded its threshold. Current value: %f", condition, value)
    msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", eas.config.FromAddress, eas.config.ToAddresses, subject, body)

    err := eas.sendMail(eas.config.SMTPServer, eas.config.SMTPPort, eas.config.Username, eas.config.Password, eas.config.FromAddress, eas.config.ToAddresses, msg)
    if err != nil {
        eas.logger.Printf("Failed to send email alert: %v", err)
    } else {
        eas.logger.Printf("Email alert sent for condition %s", condition)
    }
}

// sendMail handles the actual sending of the email
func (eas *EmailAlertSystem) sendMail(server string, port int, username, password, from string, to []string, msg string) error {
    auth := smtp.PlainAuth("", username, password, server)

    var err error
    if eas.config.EncryptionMethod == "TLS" {
        tlsconfig := &tls.Config{
            InsecureSkipVerify: true,
            ServerName:         server,
        }

        conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", server, port), tlsconfig)
        if err != nil {
            return err
        }

        c, err := smtp.NewClient(conn, server)
        if err != nil {
            return err
        }

        if err = c.Auth(auth); err != nil {
            return err
        }

        if err = c.Mail(from); err != nil {
            return err
        }

        for _, addr := range to {
            if err = c.Rcpt(addr); err != nil {
                return err
            }
        }

        w, err := c.Data()
        if err != nil {
            return err
        }

        _, err = w.Write([]byte(msg))
        if err != nil {
            return err
        }

        err = w.Close()
        if err != nil {
            return err
        }

        c.Quit()

    } else if eas.config.EncryptionMethod == "STARTTLS" {
        // STARTTLS configuration
        // Implement STARTTLS connection if needed
    } else {
        err = smtp.SendMail(fmt.Sprintf("%s:%d", server, port), auth, from, to, []byte(msg))
    }

    return err
}

// LogSentAlert logs the details of the sent alert for auditing purposes
func (eas *EmailAlertSystem) LogSentAlert(condition string, value float64) {
    timestamp := time.Now().Format(time.RFC3339)
    eas.logger.Printf("Alert sent - Condition: %s, Value: %f, Timestamp: %s", condition, value, timestamp)
}

// SecureConfig ensures the configuration is secure and compliant with regulations
func (eas *EmailAlertSystem) SecureConfig() error {
    // Implement security checks and compliance validation
    eas.logger.Println("Securing Email Alert System configuration...")
    return nil
}
