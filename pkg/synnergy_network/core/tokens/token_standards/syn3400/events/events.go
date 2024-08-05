package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	EventID        string    `json:"event_id"`
	EventType      string    `json:"event_type"`
	Timestamp      time.Time `json:"timestamp"`
	Details        string    `json:"details"`
}

type EventLogging struct {
	Events map[string]Event
	mutex  sync.Mutex
}

type Notification struct {
	NotificationID string    `json:"notification_id"`
	Recipient      string    `json:"recipient"`
	Message        string    `json:"message"`
	Timestamp      time.Time `json:"timestamp"`
	Read           bool      `json:"read"`
}

type Notifications struct {
	Notifications map[string]Notification
	mutex         sync.Mutex
}

// InitializeEventLogging initializes the EventLogging structure
func InitializeEventLogging() *EventLogging {
	return &EventLogging{
		Events: make(map[string]Event),
	}
}

// LogEvent logs a new event into the system
func (el *EventLogging) LogEvent(eventID, eventType, details string) error {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	if _, exists := el.Events[eventID]; exists {
		return errors.New("event already exists")
	}

	el.Events[eventID] = Event{
		EventID:        eventID,
		EventType:      eventType,
		Timestamp:      time.Now(),
		Details:        details,
	}

	return nil
}

// GetEvent retrieves the details of a logged event
func (el *EventLogging) GetEvent(eventID string) (Event, error) {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	event, exists := el.Events[eventID]
	if !exists {
		return Event{}, errors.New("event not found")
	}

	return event, nil
}

// SaveEventsToFile saves the logged events to a file
func (el *EventLogging) SaveEventsToFile(filename string) error {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	data, err := json.Marshal(el.Events)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadEventsFromFile loads the logged events from a file
func (el *EventLogging) LoadEventsFromFile(filename string) error {
	el.mutex.Lock()
	defer el.mutex.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &el.Events)
}

// DisplayEvent displays the details of a logged event in a readable format
func (el *EventLogging) DisplayEvent(eventID string) error {
	event, err := el.GetEvent(eventID)
	if err != nil {
		return err
	}

	fmt.Printf("Event ID: %s\nEvent Type: %s\nTimestamp: %s\nDetails: %s\n", event.EventID, event.EventType, event.Timestamp, event.Details)
	return nil
}

// InitializeNotifications initializes the Notifications structure
func InitializeNotifications() *Notifications {
	return &Notifications{
		Notifications: make(map[string]Notification),
	}
}

// SendNotification sends a new notification to a recipient
func (n *Notifications) SendNotification(notificationID, recipient, message string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if _, exists := n.Notifications[notificationID]; exists {
		return errors.New("notification already exists")
	}

	n.Notifications[notificationID] = Notification{
		NotificationID: notificationID,
		Recipient:      recipient,
		Message:        message,
		Timestamp:      time.Now(),
		Read:           false,
	}

	return nil
}

// MarkAsRead marks a notification as read
func (n *Notifications) MarkAsRead(notificationID string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	notification, exists := n.Notifications[notificationID]
	if !exists {
		return errors.New("notification not found")
	}

	notification.Read = true
	n.Notifications[notificationID] = notification

	return nil
}

// GetNotification retrieves the details of a notification
func (n *Notifications) GetNotification(notificationID string) (Notification, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	notification, exists := n.Notifications[notificationID]
	if !exists {
		return Notification{}, errors.New("notification not found")
	}

	return notification, nil
}

// SaveNotificationsToFile saves the notifications to a file
func (n *Notifications) SaveNotificationsToFile(filename string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	data, err := json.Marshal(n.Notifications)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadNotificationsFromFile loads the notifications from a file
func (n *Notifications) LoadNotificationsFromFile(filename string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &n.Notifications)
}

// DisplayNotification displays the details of a notification in a readable format
func (n *Notifications) DisplayNotification(notificationID string) error {
	notification, err := n.GetNotification(notificationID)
	if err != nil {
		return err
	}

	fmt.Printf("Notification ID: %s\nRecipient: %s\nMessage: %s\nTimestamp: %s\nRead: %t\n", notification.NotificationID, notification.Recipient, notification.Message, notification.Timestamp, notification.Read)
	return nil
}
