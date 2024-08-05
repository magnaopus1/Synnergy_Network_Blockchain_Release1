package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// NotificationType represents different types of notifications
type NotificationType string

const (
	NotificationPaymentDue   NotificationType = "payment_due"
	NotificationLatePayment  NotificationType = "late_payment"
	NotificationProposal     NotificationType = "proposal"
)

// Notification represents a notification to a stakeholder
type Notification struct {
	NotificationID string          `json:"notification_id"`
	StakeholderID  string          `json:"stakeholder_id"`
	Type           NotificationType `json:"type"`
	Message        string          `json:"message"`
	CreationDate   time.Time       `json:"creation_date"`
	Read           bool            `json:"read"`
}

// StakeholderEngagement manages stakeholder engagement for debt instruments
type StakeholderEngagement struct {
	mu sync.Mutex
	notifications map[string]Notification
}

// NewStakeholderEngagement creates a new instance of StakeholderEngagement
func NewStakeholderEngagement() *StakeholderEngagement {
	return &StakeholderEngagement{
		notifications: make(map[string]Notification),
	}
}

// NotifyStakeholder sends a notification to a stakeholder
func (se *StakeholderEngagement) NotifyStakeholder(stakeholderID string, notificationType NotificationType, message string) (string, error) {
	se.mu.Lock()
	defer se.mu.Unlock()

	notificationID := generateNotificationID()
	creationDate := time.Now()

	notification := Notification{
		NotificationID: notificationID,
		StakeholderID:  stakeholderID,
		Type:           notificationType,
		Message:        message,
		CreationDate:   creationDate,
		Read:           false,
	}

	se.notifications[notificationID] = notification
	err := saveNotificationToStorage(notification)
	if err != nil {
		return "", err
	}

	return notificationID, nil
}

// MarkNotificationAsRead marks a notification as read
func (se *StakeholderEngagement) MarkNotificationAsRead(notificationID string) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	notification, exists := se.notifications[notificationID]
	if !exists {
		return errors.New("notification not found")
	}

	notification.Read = true
	se.notifications[notificationID] = notification
	return saveNotificationToStorage(notification)
}

// GetNotifications retrieves all notifications for a stakeholder
func (se *StakeholderEngagement) GetNotifications(stakeholderID string) ([]Notification, error) {
	se.mu.Lock()
	defer se.mu.Unlock()

	var notifications []Notification
	for _, notification := range se.notifications {
		if notification.StakeholderID == stakeholderID {
			notifications = append(notifications, notification)
		}
	}

	if len(notifications) == 0 {
		return nil, errors.New("no notifications found for the specified stakeholder ID")
	}

	return notifications, nil
}

// generateNotificationID generates a unique ID for the notification
func generateNotificationID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-notification-id"
}

// saveNotificationToStorage securely stores notification data
func saveNotificationToStorage(notification Notification) error {
	data, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("notification", notification.NotificationID, encryptedData)
}

// deleteNotificationFromStorage deletes notification data from storage
func deleteNotificationFromStorage(notificationID string) error {
	return storage.Delete("notification", notificationID)
}
