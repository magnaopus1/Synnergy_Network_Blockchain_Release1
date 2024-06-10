package loan_services

import (
	"encoding/json"
	"log"
	"net/smtp"
	"time"

	"github.com/pkg/errors"
)

// NotificationService handles the creation and dispatch of loan-related notifications.
type NotificationService struct {
	smtpServer string
	smtpPort   string
	username   string
	password   string
}

// NewNotificationService initializes a NotificationService with SMTP server details.
func NewNotificationService(server, port, user, pass string) *NotificationService {
	return &NotificationService{
		smtpServer: server,
		smtpPort:   port,
		username:   user,
		password:   pass,
	}
}

// Notification defines the structure of a loan notification.
type Notification struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// SendNotification sends an email notification to the customer.
func (ns *NotificationService) SendNotification(notif Notification) error {
	auth := smtp.PlainAuth("", ns.username, ns.password, ns.smtpServer)
	to := []string{notif.To}
	msg := []byte("To: " + notif.To + "\r\n" +
		"Subject: " + notif.Subject + "\r\n" +
		"\r\n" +
		notif.Message + "\r\n")
	addr := ns.smtpServer + ":" + ns.smtpPort

	err := smtp.SendMail(addr, auth, ns.username, to, msg)
	if err != nil {
		log.Printf("Failed to send notification to %s: %v", notif.To, err)
		return errors.Wrap(err, "failed to send email notification")
	}

	log.Printf("Notification sent to %s", notif.To)
	return nil
}

// GenerateLoanApprovalNotification creates a notification for loan approval.
func (ns *NotificationService) GenerateLoanApprovalNotification(to string) Notification {
	subject := "Loan Approval Confirmation"
	message := "Congratulations! Your loan has been approved. Please check your account for more details."
	return Notification{To: to, Subject: subject, Message: message}
}

// GeneratePaymentReminder creates a notification for an upcoming payment.
func (ns *NotificationService) GeneratePaymentReminder(to string, dueDate time.Time) Notification {
	subject := "Loan Payment Reminder"
	message := "Reminder: Your loan payment is due on " + dueDate.Format("January 2, 2006") + ". Please ensure your account has sufficient funds."
	return Notification{To: to, Subject: subject, Message: message}
}

// MarshalNotification converts a Notification object into a JSON string.
func MarshalNotification(notif Notification) (string, error) {
	data, err := json.Marshal(notif)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal notification")
	}
	return string(data), nil
}

// UnmarshalNotification converts a JSON string back into a Notification object.
func UnmarshalNotification(data string) (Notification, error) {
	var notif Notification
	err := json.Unmarshal([]byte(data), &notif)
	if err != nil {
		return Notification{}, errors.Wrap(err, "failed to unmarshal notification")
	}
	return notif, nil
}
