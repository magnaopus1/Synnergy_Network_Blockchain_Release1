package alerting_and_notifications

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AlertLevel represents the severity level of an alert.
type AlertLevel int

const (
	INFO AlertLevel = iota
	WARNING
	CRITICAL
)

// Alert represents an alert that can be sent to users.
type Alert struct {
	ID        string     `json:"id"`
	Level     AlertLevel `json:"level"`
	Message   string     `json:"message"`
	Timestamp time.Time  `json:"timestamp"`
}

// AlertService manages alerts and notifications.
type AlertService struct {
	alerts     map[string]Alert
	alertsLock sync.RWMutex
	subscribers map[string]chan Alert
	subscribersLock sync.RWMutex
}

// NewAlertService creates a new AlertService.
func NewAlertService() *AlertService {
	return &AlertService{
		alerts:     make(map[string]Alert),
		subscribers: make(map[string]chan Alert),
	}
}

// GenerateAlertID generates a unique ID for an alert.
func GenerateAlertID() string {
	return fmt.Sprintf("alert-%d", time.Now().UnixNano())
}

// SendAlert sends an alert to all subscribers.
func (s *AlertService) SendAlert(level AlertLevel, message string) {
	alert := Alert{
		ID:        GenerateAlertID(),
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
	}

	s.alertsLock.Lock()
	s.alerts[alert.ID] = alert
	s.alertsLock.Unlock()

	s.notifySubscribers(alert)
}

// notifySubscribers notifies all subscribers of a new alert.
func (s *AlertService) notifySubscribers(alert Alert) {
	s.subscribersLock.RLock()
	defer s.subscribersLock.RUnlock()

	for _, ch := range s.subscribers {
		ch <- alert
	}
}

// Subscribe allows a user to subscribe to alerts.
func (s *AlertService) Subscribe(subscriberID string) (<-chan Alert, error) {
	s.subscribersLock.Lock()
	defer s.subscribersLock.Unlock()

	if _, exists := s.subscribers[subscriberID]; exists {
		return nil, errors.New("subscriber already exists")
	}

	ch := make(chan Alert, 100)
	s.subscribers[subscriberID] = ch

	return ch, nil
}

// Unsubscribe allows a user to unsubscribe from alerts.
func (s *AlertService) Unsubscribe(subscriberID string) error {
	s.subscribersLock.Lock()
	defer s.subscribersLock.Unlock()

	if _, exists := s.subscribers[subscriberID]; !exists {
		return errors.New("subscriber does not exist")
	}

	close(s.subscribers[subscriberID])
	delete(s.subscribers, subscriberID)

	return nil
}

// GetAlerts returns all alerts.
func (s *AlertService) GetAlerts() []Alert {
	s.alertsLock.RLock()
	defer s.alertsLock.RUnlock()

	alerts := make([]Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		alerts = append(alerts, alert)
	}

	return alerts
}

// ServeHTTP handles HTTP requests for alerts.
func (s *AlertService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetAlerts(w, r)
	case http.MethodPost:
		s.handleSendAlert(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *AlertService) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.GetAlerts()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (s *AlertService) handleSendAlert(w http.ResponseWriter, r *http.Request) {
	var alert Alert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.SendAlert(alert.Level, alert.Message)
	w.WriteHeader(http.StatusNoContent)
}

// Example Usage of the AlertService
func main() {
	alertService := NewAlertService()

	// Start the HTTP server for alert service
	go func() {
		http.Handle("/alerts", alertService)
		http.ListenAndServe(":8080", nil)
	}()

	// Simulate sending alerts
	go func() {
		for {
			time.Sleep(10 * time.Second)
			alertService.SendAlert(INFO, "This is an informational alert.")
			alertService.SendAlert(WARNING, "This is a warning alert.")
			alertService.SendAlert(CRITICAL, "This is a critical alert.")
		}
	}()

	// Simulate a subscriber
	subscriberID := "subscriber-1"
	alerts, _ := alertService.Subscribe(subscriberID)
	go func() {
		for alert := range alerts {
			fmt.Printf("Received alert: %+v\n", alert)
		}
	}()

	// Keep the main function running
	select {}
}
