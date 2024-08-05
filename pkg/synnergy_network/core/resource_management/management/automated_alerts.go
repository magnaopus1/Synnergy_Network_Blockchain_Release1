// Package management handles the management aspects of resource allocation, including automated alerts for the Synnergy Network.
package management

import (
    "fmt"
    "time"
    "log"
    "sync"
    "encoding/json"
    "net/smtp"
    "os"
)

// AlertType defines the type of alert
type AlertType string

const (
    CPUUsageHigh        AlertType = "CPU_USAGE_HIGH"
    MemoryUsageHigh     AlertType = "MEMORY_USAGE_HIGH"
    BandwidthUsageHigh  AlertType = "BANDWIDTH_USAGE_HIGH"
    TransactionVolumeHigh AlertType = "TRANSACTION_VOLUME_HIGH"
    NodeDown            AlertType = "NODE_DOWN"
    UnauthorizedAccess  AlertType = "UNAUTHORIZED_ACCESS"
)

// Alert defines the structure of an alert
type Alert struct {
    Timestamp   time.Time
    NodeID      string
    AlertType   AlertType
    Message     string
    Resolved    bool
    Notified    bool
}

// AlertManager handles the creation, management, and notification of alerts
type AlertManager struct {
    alerts      []Alert
    alertMutex  sync.Mutex
    smtpServer  string
    smtpPort    int
    emailSender string
    emailPassword string
    notificationRecipients []string
}

// NewAlertManager initializes a new AlertManager with SMTP configuration for sending email notifications
func NewAlertManager(smtpServer string, smtpPort int, emailSender, emailPassword string, notificationRecipients []string) *AlertManager {
    return &AlertManager{
        alerts:                []Alert{},
        smtpServer:            smtpServer,
        smtpPort:              smtpPort,
        emailSender:           emailSender,
        emailPassword:         emailPassword,
        notificationRecipients: notificationRecipients,
    }
}

// AddAlert adds a new alert to the manager and triggers notifications if necessary
func (am *AlertManager) AddAlert(alert Alert) {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()

    // Log the alert
    log.Printf("Alert added: %s - %s", alert.AlertType, alert.Message)

    // Check if similar alert exists and is unresolved
    for i, existingAlert := range am.alerts {
        if existingAlert.AlertType == alert.AlertType && existingAlert.NodeID == alert.NodeID && !existingAlert.Resolved {
            log.Printf("Existing unresolved alert found: %s. No duplicate notification sent.", existingAlert.AlertType)
            return
        }
    }

    // Add the new alert to the list
    am.alerts = append(am.alerts, alert)

    // Send notifications if not already sent
    if !alert.Notified {
        err := am.sendNotification(alert)
        if err != nil {
            log.Printf("Failed to send notification: %v", err)
        }
    }
}

// sendNotification sends an email notification for the given alert
func (am *AlertManager) sendNotification(alert Alert) error {
    subject := fmt.Sprintf("Alert: %s - Node: %s", alert.AlertType, alert.NodeID)
    body := fmt.Sprintf("Timestamp: %s\nNodeID: %s\nAlertType: %s\nMessage: %s\n", alert.Timestamp.Format(time.RFC3339), alert.NodeID, alert.AlertType, alert.Message)

    message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", am.emailSender, am.notificationRecipients, subject, body)

    err := smtp.SendMail(
        fmt.Sprintf("%s:%d", am.smtpServer, am.smtpPort),
        smtp.PlainAuth("", am.emailSender, am.emailPassword, am.smtpServer),
        am.emailSender,
        am.notificationRecipients,
        []byte(message),
    )

    if err != nil {
        log.Printf("Error sending email notification: %v", err)
        return err
    }

    // Mark alert as notified
    am.markAlertAsNotified(alert)

    log.Printf("Notification sent for alert: %s - Node: %s", alert.AlertType, alert.NodeID)
    return nil
}

// markAlertAsNotified marks an alert as notified
func (am *AlertManager) markAlertAsNotified(alert Alert) {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()

    for i, a := range am.alerts {
        if a == alert {
            am.alerts[i].Notified = true
            break
        }
    }
}

// ResolveAlert marks an alert as resolved based on NodeID and AlertType
func (am *AlertManager) ResolveAlert(nodeID string, alertType AlertType) {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()

    for i, alert := range am.alerts {
        if alert.NodeID == nodeID && alert.AlertType == alertType {
            am.alerts[i].Resolved = true
            log.Printf("Alert resolved: %s - Node: %s", alert.AlertType, nodeID)
        }
    }
}

// GetAlerts returns all alerts
func (am *AlertManager) GetAlerts() []Alert {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()
    return am.alerts
}

// SaveAlertsToFile saves all alerts to a specified JSON file
func (am *AlertManager) SaveAlertsToFile(filename string) error {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()

    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    return encoder.Encode(am.alerts)
}

// LoadAlertsFromFile loads alerts from a specified JSON file
func (am *AlertManager) LoadAlertsFromFile(filename string) error {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()

    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    return decoder.Decode(&am.alerts)
}

// RemoveResolvedAlerts removes alerts that have been marked as resolved
func (am *AlertManager) RemoveResolvedAlerts() {
    am.alertMutex.Lock()
    defer am.alertMutex.Unlock()

    unresolvedAlerts := []Alert{}
    for _, alert := range am.alerts {
        if !alert.Resolved {
            unresolvedAlerts = append(unresolvedAlerts, alert)
        }
    }
    am.alerts = unresolvedAlerts
}
