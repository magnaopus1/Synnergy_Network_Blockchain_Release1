package events

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// EventType defines the type of event.
type EventType string

const (
	EventTokenIssued     EventType = "TokenIssued"
	EventTokenRedeemed   EventType = "TokenRedeemed"
	EventCouponPaid      EventType = "CouponPaid"
	EventInterestPaid    EventType = "InterestPaid"
	EventOwnershipTransferred EventType = "OwnershipTransferred"
	EventComplianceChecked EventType = "ComplianceChecked"
	EventSystemUpdate EventType = "SystemUpdate"
	EventSecurityBreachDetected EventType = "SecurityBreachDetected"
)

// Event represents a system event that has occurred.
type Event struct {
	ID          string    `json:"id"`
	Type        EventType `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Details     string    `json:"details"`
}

// EventLogger manages logging of events.
type EventLogger struct {
	logFile  *os.File
	logChan  chan Event
	quitChan chan bool
}

// NewEventLogger initializes a new event logger.
func NewEventLogger(logFilePath string) (*EventLogger, error) {
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	logger := &EventLogger{
		logFile:  file,
		logChan:  make(chan Event, 100),
		quitChan: make(chan bool),
	}

	go logger.listen()
	return logger, nil
}

// LogEvent logs an event to the file and console.
func (el *EventLogger) LogEvent(event Event) {
	select {
	case el.logChan <- event:
	default:
		log.Println("EventLogger buffer is full, dropping event:", event)
	}
}

// Close closes the event logger and ensures all events are logged.
func (el *EventLogger) Close() {
	el.quitChan <- true
	el.logFile.Close()
}

func (el *EventLogger) listen() {
	for {
		select {
		case event := <-el.logChan:
			el.writeEvent(event)
		case <-el.quitChan:
			close(el.logChan)
			for event := range el.logChan {
				el.writeEvent(event)
			}
			return
		}
	}
}

func (el *EventLogger) writeEvent(event Event) {
	logLine := formatEvent(event)
	log.Println(logLine)
	if el.logFile != nil {
		if _, err := el.logFile.WriteString(logLine + "\n"); err != nil {
			log.Println("Failed to write event to log file:", err)
		}
	}
}

func formatEvent(event Event) string {
	eventData, err := json.Marshal(event)
	if err != nil {
		log.Println("Error marshaling event:", err)
		return ""
	}
	return string(eventData)
}

// Notification represents a notification to be sent to users.
type Notification struct {
	Recipient   string    `json:"recipient"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
}

// NotificationService manages sending notifications to users.
type NotificationService struct {
	notificationChan chan Notification
}

// NewNotificationService initializes a new notification service.
func NewNotificationService() *NotificationService {
	return &NotificationService{
		notificationChan: make(chan Notification, 100),
	}
}

// SendNotification sends a notification to a user.
func (ns *NotificationService) SendNotification(notification Notification) {
	select {
	case ns.notificationChan <- notification:
	default:
		log.Println("NotificationService buffer is full, dropping notification:", notification)
	}
}

// Start starts the notification service.
func (ns *NotificationService) Start() {
	go func() {
		for notification := range ns.notificationChan {
			ns.send(notification)
		}
	}()
}

// Stop stops the notification service.
func (ns *NotificationService) Stop() {
	close(ns.notificationChan)
}

func (ns *NotificationService) send(notification Notification) {
	// In a real implementation, this would send the notification via email, SMS, push notification, etc.
	log.Printf("Sending notification to %s: %s - %s\n", notification.Recipient, notification.Title, notification.Message)
}

// EventNotifier combines event logging with notifications.
type EventNotifier struct {
	logger        *EventLogger
	notificationService *NotificationService
}

// NewEventNotifier creates a new event notifier.
func NewEventNotifier(logger *EventLogger, notificationService *NotificationService) *EventNotifier {
	return &EventNotifier{
		logger:        logger,
		notificationService: notificationService,
	}
}

// NotifyEvent logs the event and sends a notification.
func (en *EventNotifier) NotifyEvent(event Event, notification Notification) {
	en.logger.LogEvent(event)
	en.notificationService.SendNotification(notification)
}
