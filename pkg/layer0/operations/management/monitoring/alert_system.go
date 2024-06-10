package monitoring

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"
)

// Alert represents an alert message
type Alert struct {
	ID          string
	Severity    string
	Message     string
	Timestamp   time.Time
	Resolved    bool
	NodeID      string
	Metric      string
	CurrentValue float64
	Threshold   float64
}

// AlertSystem represents the alert system for the blockchain network
type AlertSystem struct {
	Alerts         []Alert
	EmailRecipients []string
	SMTPServer      string
	SMTPPort        int
	SMTPUser        string
	SMTPPassword    string
}

// NewAlertSystem initializes a new AlertSystem instance
func NewAlertSystem(emailRecipients []string, smtpServer string, smtpPort int, smtpUser, smtpPassword string) *AlertSystem {
	return &AlertSystem{
		Alerts:         []Alert{},
		EmailRecipients: emailRecipients,
		SMTPServer:      smtpServer,
		SMTPPort:        smtpPort,
		SMTPUser:        smtpUser,
		SMTPPassword:    smtpPassword,
	}
}

// GenerateAlert generates a new alert and sends notifications
func (as *AlertSystem) GenerateAlert(nodeID, severity, message, metric string, currentValue, threshold float64) {
	alert := Alert{
		ID:          fmt.Sprintf("%d", len(as.Alerts)+1),
		Severity:    severity,
		Message:     message,
		Timestamp:   time.Now(),
		Resolved:    false,
		NodeID:      nodeID,
		Metric:      metric,
		CurrentValue: currentValue,
		Threshold:   threshold,
	}
	as.Alerts = append(as.Alerts, alert)

	as.sendEmailNotification(alert)
}

// ResolveAlert resolves an alert by its ID
func (as *AlertSystem) ResolveAlert(alertID string) error {
	for i := range as.Alerts {
		if as.Alerts[i].ID == alertID {
			as.Alerts[i].Resolved = true
			return nil
		}
	}
	return fmt.Errorf("alert with ID %s not found", alertID)
}

// GetUnresolvedAlerts returns a list of unresolved alerts
func (as *AlertSystem) GetUnresolvedAlerts() []Alert {
	unresolved := []Alert{}
	for _, alert := range as.Alerts {
		if !alert.Resolved {
			unresolved = append(unresolved, alert)
		}
	}
	return unresolved
}

// sendEmailNotification sends an email notification for the alert
func (as *AlertSystem) sendEmailNotification(alert Alert) {
	subject := fmt.Sprintf("Blockchain Alert: %s", alert.Severity)
	body := fmt.Sprintf("Alert ID: %s\nSeverity: %s\nMessage: %s\nTimestamp: %s\nNode ID: %s\nMetric: %s\nCurrent Value: %.2f\nThreshold: %.2f",
		alert.ID, alert.Severity, alert.Message, alert.Timestamp.Format(time.RFC1123), alert.NodeID, alert.Metric, alert.CurrentValue, alert.Threshold)

	message := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)
	recipients := strings.Join(as.EmailRecipients, ",")
	err := smtp.SendMail(fmt.Sprintf("%s:%d", as.SMTPServer, as.SMTPPort),
		smtp.PlainAuth("", as.SMTPUser, as.SMTPPassword, as.SMTPServer),
		as.SMTPUser, as.EmailRecipients, []byte(message))

	if err != nil {
		log.Printf("Failed to send alert email: %v", err)
	}
}

// MonitorNodeMetrics continuously monitors node metrics and generates alerts
func (as *AlertSystem) MonitorNodeMetrics(nodeMetricsChan <-chan NodeMetric) {
	for metric := range nodeMetricsChan {
		if metric.CPUUsage > 90.0 {
			as.GenerateAlert(metric.NodeID, "Critical", "High CPU usage detected", "CPUUsage", metric.CPUUsage, 90.0)
		}
		if metric.MemoryUsage > 90.0 {
			as.GenerateAlert(metric.NodeID, "Critical", "High Memory usage detected", "MemoryUsage", metric.MemoryUsage, 90.0)
		}
		if metric.DiskUsage > 90.0 {
			as.GenerateAlert(metric.NodeID, "Critical", "High Disk usage detected", "DiskUsage", metric.DiskUsage, 90.0)
		}
	}
}

// NodeMetric represents performance metrics of a node
type NodeMetric struct {
	NodeID      string
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Timestamp   time.Time
}

func main() {
	// Example usage of the AlertSystem
	emailRecipients := []string{"admin@example.com"}
	smtpServer := "smtp.example.com"
	smtpPort := 587
	smtpUser := "user@example.com"
	smtpPassword := "password"

	alertSystem := NewAlertSystem(emailRecipients, smtpServer, smtpPort, smtpUser, smtpPassword)

	// Example node metrics channel
	nodeMetricsChan := make(chan NodeMetric)

	// Simulate node metrics data
	go func() {
		for {
			nodeMetricsChan <- NodeMetric{
				NodeID:      "node1",
				CPUUsage:    95.0,
				MemoryUsage: 85.0,
				DiskUsage:   92.0,
				Timestamp:   time.Now(),
			}
			time.Sleep(10 * time.Second)
		}
	}()

	// Start monitoring node metrics
	go alertSystem.MonitorNodeMetrics(nodeMetricsChan)

	// Keep the main function running
	select {}
}
