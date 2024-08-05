package alerting_and_notifications

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/core/network"
)

// Alert represents a real-time alert in the system
type Alert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	Resolved    bool      `json:"resolved"`
	Resolution  string    `json:"resolution,omitempty"`
	ResolvedAt  time.Time `json:"resolved_at,omitempty"`
}

// AlertService handles the creation, notification, and resolution of alerts
type AlertService struct {
	storage  storage.Storage
	security security.Encryption
}

// NewAlertService creates a new instance of AlertService
func NewAlertService(storage storage.Storage, security security.Encryption) *AlertService {
	return &AlertService{
		storage:  storage,
		security: security,
	}
}

// CreateAlert creates a new alert and notifies relevant channels
func (s *AlertService) CreateAlert(ctx context.Context, alert Alert) error {
	alert.ID = generateID()
	alert.Timestamp = time.Now()

	// Encrypt the alert message
	encryptedMessage, err := s.security.Encrypt([]byte(alert.Message))
	if err != nil {
		return err
	}
	alert.Message = encryptedMessage

	// Store the alert in storage
	alertData, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	err = s.storage.Save(ctx, alert.ID, alertData)
	if err != nil {
		return err
	}

	// Notify relevant channels
	err = s.notifyChannels(ctx, alert)
	if err != nil {
		return err
	}

	return nil
}

// notifyChannels sends the alert notification to configured channels
func (s *AlertService) notifyChannels(ctx context.Context, alert Alert) error {
	// Send notifications to configured channels
	// Implement actual notification logic (e.g., email, SMS, push notification)
	log.Printf("Sending notification for alert ID: %s, Type: %s, Severity: %s", alert.ID, alert.Type, alert.Severity)
	return nil
}

// ResolveAlert resolves an existing alert
func (s *AlertService) ResolveAlert(ctx context.Context, alertID, resolution string) error {
	alertData, err := s.storage.Get(ctx, alertID)
	if err != nil {
		return err
	}

	var alert Alert
	err = json.Unmarshal(alertData, &alert)
	if err != nil {
		return err
	}

	alert.Resolved = true
	alert.Resolution = resolution
	alert.ResolvedAt = time.Now()

	updatedAlertData, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	err = s.storage.Save(ctx, alertID, updatedAlertData)
	if err != nil {
		return err
	}

	log.Printf("Resolved alert ID: %s", alert.ID)
	return nil
}

// ListAlerts lists all alerts with optional filtering
func (s *AlertService) ListAlerts(ctx context.Context, filter map[string]string) ([]Alert, error) {
	alertsData, err := s.storage.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	var alerts []Alert
	for _, data := range alertsData {
		var alert Alert
		err := json.Unmarshal(data, &alert)
		if err != nil {
			return nil, err
		}
		// Decrypt the alert message
		decryptedMessage, err := s.security.Decrypt([]byte(alert.Message))
		if err != nil {
			return nil, err
		}
		alert.Message = decryptedMessage

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// generateID generates a unique identifier for alerts
func generateID() string {
	return network.GenerateUUID()
}
