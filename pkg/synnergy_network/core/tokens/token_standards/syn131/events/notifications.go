package events

import (
	"fmt"
	"sync"
	"time"
)

// NotificationType defines the type of notifications that can be sent.
type NotificationType string

const (
	// NotificationTypeInfo is for informational notifications.
	NotificationTypeInfo NotificationType = "INFO"
	// NotificationTypeWarning is for warning notifications.
	NotificationTypeWarning NotificationType = "WARNING"
	// NotificationTypeError is for error notifications.
	NotificationTypeError NotificationType = "ERROR"
)

// Notification represents a notification message in the system.
type Notification struct {
	Type      NotificationType
	Message   string
	Timestamp time.Time
}

// NotificationListener defines the interface for listening to notifications.
type NotificationListener interface {
	HandleNotification(notification Notification)
}

// NotificationDispatcher is responsible for dispatching notifications to listeners.
type NotificationDispatcher struct {
	listeners map[NotificationType][]NotificationListener
	mutex     sync.RWMutex
}

// NewNotificationDispatcher creates a new NotificationDispatcher.
func NewNotificationDispatcher() *NotificationDispatcher {
	return &NotificationDispatcher{
		listeners: make(map[NotificationType][]NotificationListener),
	}
}

// RegisterListener registers a listener for a specific notification type.
func (nd *NotificationDispatcher) RegisterListener(notificationType NotificationType, listener NotificationListener) {
	nd.mutex.Lock()
	defer nd.mutex.Unlock()

	if _, exists := nd.listeners[notificationType]; !exists {
		nd.listeners[notificationType] = []NotificationListener{}
	}
	nd.listeners[notificationType] = append(nd.listeners[notificationType], listener)
}

// UnregisterListener unregisters a listener for a specific notification type.
func (nd *NotificationDispatcher) UnregisterListener(notificationType NotificationType, listener NotificationListener) {
	nd.mutex.Lock()
	defer nd.mutex.Unlock()

	if listeners, exists := nd.listeners[notificationType]; exists {
		for i, l := range listeners {
			if l == listener {
				nd.listeners[notificationType] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
	}
}

// DispatchNotification dispatches a notification to all registered listeners.
func (nd *NotificationDispatcher) DispatchNotification(notificationType NotificationType, message string) {
	nd.mutex.RLock()
	defer nd.mutex.RUnlock()

	notification := Notification{
		Type:      notificationType,
		Message:   message,
		Timestamp: time.Now(),
	}

	if listeners, exists := nd.listeners[notificationType]; exists {
		for _, listener := range listeners {
			go listener.HandleNotification(notification)
		}
	}
}

// ConcreteNotificationListener is an example implementation of a NotificationListener.
type ConcreteNotificationListener struct {
	ID string
}

// NewConcreteNotificationListener creates a new instance of ConcreteNotificationListener.
func NewConcreteNotificationListener(id string) *ConcreteNotificationListener {
	return &ConcreteNotificationListener{
		ID: id,
	}
}

// HandleNotification handles an incoming notification.
func (listener *ConcreteNotificationListener) HandleNotification(notification Notification) {
	// Implement the business logic for handling the notification here.
	fmt.Printf("Listener %s received notification: %v at %v with message: %s\n", listener.ID, notification.Type, notification.Timestamp, notification.Message)
}

