package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Notification represents a notification event
type Notification struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Recipient string    `json:"recipient"`
}

// NotificationManager manages sending notifications
type NotificationManager struct {
	mu           sync.Mutex
	notifications map[string]Notification
	webhookURL    string
}

// NewNotificationManager initializes a new NotificationManager
func NewNotificationManager(webhookURL string) *NotificationManager {
	return &NotificationManager{
		notifications: make(map[string]Notification),
		webhookURL:    webhookURL,
	}
}

// SendNotification sends a new notification
func (nm *NotificationManager) SendNotification(notificationType, message, recipient string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	notificationID := uuid.New().String()
	timestamp := time.Now()

	notification := Notification{
		ID:        notificationID,
		Timestamp: timestamp,
		Type:      notificationType,
		Message:   message,
		Recipient: recipient,
	}

	nm.notifications[notificationID] = notification

	if err := nm.sendToWebhook(notification); err != nil {
		return err
	}

	return nil
}

// GetNotification retrieves a notification by its ID
func (nm *NotificationManager) GetNotification(notificationID string) (*Notification, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	notification, exists := nm.notifications[notificationID]
	if !exists {
		return nil, errors.New("notification not found")
	}

	return &notification, nil
}

// GetNotificationsByType retrieves all notifications of a specific type
func (nm *NotificationManager) GetNotificationsByType(notificationType string) ([]Notification, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	var notifications []Notification
	for _, notification := range nm.notifications {
		if notification.Type == notificationType {
			notifications = append(notifications, notification)
		}
	}
	return notifications, nil
}

// sendToWebhook sends a notification to a configured webhook URL
func (nm *NotificationManager) sendToWebhook(notification Notification) error {
	if nm.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	payload, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	resp, err := http.Post(nm.webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send notification to webhook, status: %s", resp.Status)
	}

	return nil
}

// Setup a default notification manager for demonstration purposes
func setupDefaultNotificationManager() *NotificationManager {
	webhookURL := "https://your-webhook-url.com/notify"
	return NewNotificationManager(webhookURL)
}

func main() {
	manager := setupDefaultNotificationManager()

	// Example usage of sending a notification
	err := manager.SendNotification("INFO", "A new transaction has been recorded", "user@example.com")
	if err != nil {
		log.Fatalf("Failed to send notification: %v", err)
	}

	// Example usage of retrieving a notification
	notificationID := "your-notification-id"
	notification, err := manager.GetNotification(notificationID)
	if err != nil {
		log.Fatalf("Failed to get notification: %v", err)
	}
	log.Printf("Retrieved notification: %+v", notification)
}
