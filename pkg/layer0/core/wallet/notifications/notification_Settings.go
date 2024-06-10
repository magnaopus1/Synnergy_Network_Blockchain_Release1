package notifications

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"
)

// NotificationType represents the type of notification.
type NotificationType string

const (
	// BalanceUpdate represents a balance update notification.
	BalanceUpdate NotificationType = "BalanceUpdate"
	// TransactionReceived represents a transaction received notification.
	TransactionReceived NotificationType = "TransactionReceived"
	// TransactionSent represents a transaction sent notification.
	TransactionSent NotificationType = "TransactionSent"
)

// NotificationSettings represents the settings for notifications.
type NotificationSettings struct {
	EnableEmail    bool              `json:"enable_email"`
	EnableSMS      bool              `json:"enable_sms"`
	EnablePush     bool              `json:"enable_push"`
	SubscribedTypes map[NotificationType]bool `json:"subscribed_types"`
	EmailAddress   string            `json:"email_address"`
	PhoneNumber    string            `json:"phone_number"`
	PushToken      string            `json:"push_token"`
	mu             sync.Mutex
}

// NewNotificationSettings creates a new instance of NotificationSettings with default values.
func NewNotificationSettings() *NotificationSettings {
	return &NotificationSettings{
		EnableEmail:    true,
		EnableSMS:      true,
		EnablePush:     true,
		SubscribedTypes: make(map[NotificationType]bool),
		EmailAddress:   "",
		PhoneNumber:    "",
		PushToken:      "",
		mu:             sync.Mutex{},
	}
}

// LoadSettings loads the notification settings from a file.
func (ns *NotificationSettings) LoadSettings(filePath string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, ns)
	if err != nil {
		return err
	}

	return nil
}

// SaveSettings saves the notification settings to a file.
func (ns *NotificationSettings) SaveSettings(filePath string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	data, err := json.MarshalIndent(ns, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// UpdateSettings updates the notification settings with the provided values.
func (ns *NotificationSettings) UpdateSettings(enableEmail, enableSMS, enablePush bool, emailAddress, phoneNumber, pushToken string, subscribedTypes map[NotificationType]bool) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if emailAddress == "" && enableEmail {
		return errors.New("email address cannot be empty when email notifications are enabled")
	}
	if phoneNumber == "" && enableSMS {
		return errors.New("phone number cannot be empty when SMS notifications are enabled")
	}
	if pushToken == "" && enablePush {
		return errors.New("push token cannot be empty when push notifications are enabled")
	}

	ns.EnableEmail = enableEmail
	ns.EnableSMS = enableSMS
	ns.EnablePush = enablePush
	ns.EmailAddress = emailAddress
	ns.PhoneNumber = phoneNumber
	ns.PushToken = pushToken
	ns.SubscribedTypes = subscribedTypes

	return nil
}

// IsSubscribed checks if a particular notification type is subscribed.
func (ns *NotificationSettings) IsSubscribed(notificationType NotificationType) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	subscribed, exists := ns.SubscribedTypes[notificationType]
	return exists && subscribed
}

// Example usage of NotificationSettings.
func main() {
	settings := NewNotificationSettings()

	// Update settings
	subscribedTypes := map[NotificationType]bool{
		BalanceUpdate:       true,
		TransactionReceived: true,
		TransactionSent:     true,
	}
	err := settings.UpdateSettings(true, true, true, "user@example.com", "1234567890", "pushToken123", subscribedTypes)
	if err != nil {
		panic(err)
	}

	// Save settings to a file
	err = settings.SaveSettings("notification_settings.json")
	if err != nil {
		panic(err)
	}

	// Load settings from a file
	err = settings.LoadSettings("notification_settings.json")
	if err != nil {
		panic(err)
	}

	// Check if a notification type is subscribed
	isSubscribed := settings.IsSubscribed(BalanceUpdate)
	println("Is subscribed to BalanceUpdate:", isSubscribed)
}
