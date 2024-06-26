package notifications

import (
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// NotificationService handles sending notifications to users.
type NotificationService struct {
	clients       map[*websocket.Conn]bool
	broadcast     chan *Notification
	register      chan *websocket.Conn
	unregister    chan *websocket.Conn
	emailSettings EmailSettings
	mutex         sync.Mutex
}

// EmailSettings stores the configuration for sending email notifications.
type EmailSettings struct {
	SMTPHost     string
	SMTPPort     string
	Username     string
	Password     string
	FromAddress  string
}

// Notification represents a notification message.
type Notification struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Time    time.Time `json:"time"`
}

// NewNotificationService creates a new instance of NotificationService.
func NewNotificationService(emailSettings EmailSettings) *NotificationService {
	return &NotificationService{
		clients:       make(map[*websocket.Conn]bool),
		broadcast:     make(chan *Notification),
		register:      make(chan *websocket.Conn),
		unregister:    make(chan *websocket.Conn),
		emailSettings: emailSettings,
	}
}

// Run starts the notification service to listen for incoming and outgoing notifications.
func (ns *NotificationService) Run() {
	for {
		select {
		case client := <-ns.register:
			ns.mutex.Lock()
			ns.clients[client] = true
			ns.mutex.Unlock()
		case client := <-ns.unregister:
			ns.mutex.Lock()
			if _, ok := ns.clients[client]; ok {
				delete(ns.clients, client)
				client.Close()
			}
			ns.mutex.Unlock()
		case notification := <-ns.broadcast:
			ns.mutex.Lock()
			for client := range ns.clients {
				err := client.WriteJSON(notification)
				if err != nil {
					client.Close()
					delete(ns.clients, client)
				}
			}
			ns.mutex.Unlock()
			ns.sendEmailNotification(notification)
		}
	}
}

// RegisterClient registers a new client for websocket notifications.
func (ns *NotificationService) RegisterClient(client *websocket.Conn) {
	ns.register <- client
}

// UnregisterClient unregisters a client from websocket notifications.
func (ns *NotificationService) UnregisterClient(client *websocket.Conn) {
	ns.unregister <- client
}

// SendNotification sends a notification to all registered clients.
func (ns *NotificationService) SendNotification(notification *Notification) {
	ns.broadcast <- notification
}

// sendEmailNotification sends an email notification.
func (ns *NotificationService) sendEmailNotification(notification *Notification) {
	to := ns.emailSettings.Username
	subject := fmt.Sprintf("New Notification: %s", notification.Type)
	body := fmt.Sprintf("Time: %s\n\n%s", notification.Time.Format(time.RFC1123), notification.Message)
	msg := "From: " + ns.emailSettings.FromAddress + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	auth := smtp.PlainAuth("", ns.emailSettings.Username, ns.emailSettings.Password, ns.emailSettings.SMTPHost)
	err := smtp.SendMail(ns.emailSettings.SMTPHost+":"+ns.emailSettings.SMTPPort, auth, ns.emailSettings.FromAddress, []string{to}, []byte(msg))
	if err != nil {
		log.Printf("Failed to send email notification: %v", err)
	}
}

// HandleWebSocket handles incoming websocket connections.
func (ns *NotificationService) HandleWebSocket(conn *websocket.Conn) {
	ns.RegisterClient(conn)

	defer func() {
		ns.UnregisterClient(conn)
	}()

	for {
		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("Error reading websocket message: %v", err)
			break
		}
	}
}

// Example usage of NotificationService.
func main() {
	emailSettings := EmailSettings{
		SMTPHost:    "smtp.example.com",
		SMTPPort:    "587",
		Username:    "your-email@example.com",
		Password:    "your-password",
		FromAddress: "no-reply@example.com",
	}

	ns := NewNotificationService(emailSettings)

	// Simulate a new notification being sent every 10 seconds
	go func() {
		for {
			time.Sleep(10 * time.Second)
			notification := &Notification{
				Type:    "Balance Update",
				Message: "Your balance has been updated.",
				Time:    time.Now(),
			}
			ns.SendNotification(notification)
		}
	}()

	ns.Run()
}
