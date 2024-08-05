package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/argon2"
)

// Notification represents a blockchain event notification.
type Notification struct {
	ID        string
	Type      string
	Timestamp int64
	Recipient string
	Message   string
}

// NotificationListener defines the interface for a notification listener.
type NotificationListener interface {
	HandleNotification(notification Notification) error
}

// NotificationDispatcher is responsible for managing and dispatching notifications.
type NotificationDispatcher struct {
	listeners map[string][]NotificationListener
}

// NewNotificationDispatcher creates a new NotificationDispatcher instance.
func NewNotificationDispatcher() *NotificationDispatcher {
	return &NotificationDispatcher{
		listeners: make(map[string][]NotificationListener),
	}
}

// RegisterListener registers a notification listener for a specific notification type.
func (nd *NotificationDispatcher) RegisterListener(notificationType string, listener NotificationListener) {
	if _, ok := nd.listeners[notificationType]; !ok {
		nd.listeners[notificationType] = []NotificationListener{}
	}
	nd.listeners[notificationType] = append(nd.listeners[notificationType], listener)
}

// UnregisterListener unregisters a notification listener for a specific notification type.
func (nd *NotificationDispatcher) UnregisterListener(notificationType string, listener NotificationListener) error {
	if _, ok := nd.listeners[notificationType]; !ok {
		return errors.New("no listeners registered for this notification type")
	}

	for i, l := range nd.listeners[notificationType] {
		if l == listener {
			nd.listeners[notificationType] = append(nd.listeners[notificationType][:i], nd.listeners[notificationType][i+1:]...)
			return nil
		}
	}
	return errors.New("listener not found")
}

// DispatchNotification dispatches a notification to all registered listeners.
func (nd *NotificationDispatcher) DispatchNotification(notification Notification) {
	if listeners, ok := nd.listeners[notification.Type]; ok {
		for _, listener := range listeners {
			go listener.HandleNotification(notification)
		}
	}
}

// Utility functions for notification ID generation, encryption, and decryption

// generateNotificationID generates a unique notification ID.
func generateNotificationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// generateEncryptionKey generates a secure encryption key.
func generateEncryptionKey() string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte("passphrase"), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(key)
}

// encrypt encrypts data using AES-GCM with the provided passphrase.
func encrypt(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES-GCM with the provided passphrase.
func decrypt(encryptedData, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EmailNotificationListener sends notifications via email.
type EmailNotificationListener struct {
	SMTPServer   string
	SMTPPort     int
	Username     string
	Password     string
	FromAddress  string
	TemplatePath string
}

// HandleNotification handles email notifications.
func (enl *EmailNotificationListener) HandleNotification(notification Notification) error {
	// Implement the business logic for handling email notifications.
	// Example: sending an email to the recipient with the notification message.
	return sendEmail(enl, notification)
}

// sendEmail sends an email notification.
func sendEmail(enl *EmailNotificationListener, notification Notification) error {
	body := fmt.Sprintf("Subject: %s\n\n%s", notification.Type, notification.Message)
	auth := smtp.PlainAuth("", enl.Username, enl.Password, enl.SMTPServer)
	to := []string{notification.Recipient}
	msg := []byte(body)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", enl.SMTPServer, enl.SMTPPort), auth, enl.FromAddress, to, msg)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		return err
	}
	log.Printf("Email sent to %s: %s", notification.Recipient, notification.Message)
	return nil
}

// SMSNotificationListener sends notifications via SMS.
type SMSNotificationListener struct {
	APIEndpoint string
	APIKey      string
	SenderID    string
}

// HandleNotification handles SMS notifications.
func (snl *SMSNotificationListener) HandleNotification(notification Notification) error {
	// Implement the business logic for handling SMS notifications.
	// Example: sending an SMS to the recipient with the notification message.
	return sendSMS(snl, notification)
}

// sendSMS sends an SMS notification.
func sendSMS(snl *SMSNotificationListener, notification Notification) error {
	payload := map[string]string{
		"to":      notification.Recipient,
		"message": notification.Message,
		"sender":  snl.SenderID,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling SMS payload: %v", err)
		return err
	}

	req, err := http.NewRequest("POST", snl.APIEndpoint, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Error creating SMS request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", snl.APIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending SMS: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error response from SMS API: %v", resp.Status)
		return errors.New("failed to send SMS notification")
	}

	log.Printf("SMS sent to %s: %s", notification.Recipient, notification.Message)
	return nil
}

// PushNotificationListener sends notifications via push notification.
type PushNotificationListener struct {
	PushServiceURL string
	APIKey         string
}

// HandleNotification handles push notifications.
func (pnl *PushNotificationListener) HandleNotification(notification Notification) error {
	// Implement the business logic for handling push notifications.
	// Example: sending a push notification to the recipient with the notification message.
	return sendPushNotification(pnl, notification)
}

// sendPushNotification sends a push notification.
func sendPushNotification(pnl *PushNotificationListener, notification Notification) error {
	payload := map[string]string{
		"title":   notification.Type,
		"message": notification.Message,
		"to":      notification.Recipient,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling push notification payload: %v", err)
		return err
	}

	req, err := http.NewRequest("POST", pnl.PushServiceURL, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Error creating push notification request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", pnl.APIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending push notification: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error response from push notification service: %v", resp.Status)
		return errors.New("failed to send push notification")
	}

	log.Printf("Push notification sent to %s: %s", notification.Recipient, notification.Message)
	return nil
}

// Syn130NotificationSystem is responsible for managing and dispatching notifications specific to the SYN130 Token Standard.
type Syn130NotificationSystem struct {
	dispatcher *NotificationDispatcher
}

// NewSyn130NotificationSystem creates a new Syn130NotificationSystem instance.
func NewSyn130NotificationSystem() *Syn130NotificationSystem {
	return &Syn130NotificationSystem{
		dispatcher: NewNotificationDispatcher(),
	}
}

// RegisterStandardListeners registers standard listeners for the SYN130 Token Standard.
func (sns *Syn130NotificationSystem) RegisterStandardListeners() {
	emailNotificationListener := &EmailNotificationListener{
		SMTPServer:  "smtp.example.com",
		SMTPPort:    587,
		Username:    "username",
		Password:    "password",
		FromAddress: "no-reply@example.com",
	}
	smsNotificationListener := &SMSNotificationListener{
		APIEndpoint: "https://api.smsprovider.com/send",
		APIKey:      "your-api-key",
		SenderID:    "Syn130",
	}
	pushNotificationListener := &PushNotificationListener{
		PushServiceURL: "https://api.pushservice.com/send",
		APIKey:         "your-api-key",
	}

	sns.dispatcher.RegisterListener("email", emailNotificationListener)
	sns.dispatcher.RegisterListener("sms", smsNotificationListener)
	sns.dispatcher.RegisterListener("push", pushNotificationListener)
}

// DispatchSyn130Notification dispatches a notification specific to the SYN130 Token Standard.
func (sns *Syn130NotificationSystem) DispatchSyn130Notification(notificationType, recipient, message string) {
	notification := Notification{
		ID:        generateNotificationID(),
		Type:      notificationType,
		Timestamp: time.Now().Unix(),
		Recipient: recipient,
		Message:   message,
	}
	sns.dispatcher.DispatchNotification(notification)
}

// LoggingNotificationListener logs all notifications for auditing purposes.
type LoggingNotificationListener struct{}

// HandleNotification logs the notification details.
func (lnl *LoggingNotificationListener) HandleNotification(notification Notification) error {
	log.Printf("Notification logged: ID=%s, Type=%s, Timestamp=%d, Recipient=%s, Message=%s\n",
		notification.ID, notification.Type, notification.Timestamp, notification.Recipient, notification.Message)
	return nil
}

// Example of integrating a logging listener into the notification system.
func (sns *Syn130NotificationSystem) RegisterLoggingListener() {
	loggingNotificationListener := &LoggingNotificationListener{}
	sns.dispatcher.RegisterListener("email", loggingNotificationListener)
	sns.dispatcher.RegisterListener("sms", loggingNotificationListener)
	sns.dispatcher.RegisterListener("push", loggingNotificationListener)
}
