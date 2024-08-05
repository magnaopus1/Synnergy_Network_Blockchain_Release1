package wallet_notificationApi

import (
	"encoding/json"
	"net/http"
	"synnergy_network/core/wallet/notifications"
	"synnergy_network/utils/logger"

	"github.com/gorilla/mux"
)

var log *logger.Logger

func init() {
	var err error
	log, err = logger.NewLogger("wallet_notificationApi.log")
	if err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
}

// APIResponse is a standard response structure for the APIs
type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// HandleAddAlert handles the creation of new alerts
func HandleAddAlert(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Type        notifications.AlertType `json:"type"`
		Description string                  `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	alertManager := notifications.NewAlertManager("alerts.json")
	if err := alertManager.LoadAlerts(); err != nil {
		log.Error("Failed to load alerts: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to load alerts"})
		return
	}

	if err := alertManager.AddAlert(requestData.Type, requestData.Description); err != nil {
		log.Error("Failed to add alert: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to add alert"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Alert added successfully"})
}

// HandleListAlerts handles listing all alerts
func HandleListAlerts(w http.ResponseWriter, r *http.Request) {
	alertManager := notifications.NewAlertManager("alerts.json")
	if err := alertManager.LoadAlerts(); err != nil {
		log.Error("Failed to load alerts: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to load alerts"})
		return
	}

	alerts, err := alertManager.ListAlerts()
	if err != nil {
		log.Error("Failed to list alerts: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to list alerts"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Data: alerts})
}

// HandleHandleAlert handles marking an alert as handled
func HandleHandleAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	alertManager := notifications.NewAlertManager("alerts.json")
	if err := alertManager.LoadAlerts(); err != nil {
		log.Error("Failed to load alerts: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to load alerts"})
		return
	}

	if err := alertManager.HandleAlert(alertID); err != nil {
		log.Error("Failed to handle alert: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to handle alert"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Alert handled successfully"})
}

// HandleSendNotification handles sending notifications
func HandleSendNotification(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		UserID  string                              `json:"user_id"`
		Message notifications.NotificationMessage `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	mailer := notifications.NewMailer("smtp.example.com", "no-reply@example.com", "password")
	wsPool := notifications.NewWebSocketPool()
	notificationService := notifications.NewNotificationService("encryptionKey123", mailer, wsPool)

	if err := notificationService.SendNotification(requestData.UserID, requestData.Message); err != nil {
		log.Error("Failed to send notification: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to send notification"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Notification sent successfully"})
}

// HandleUpdateNotificationSettings handles updating notification settings
func HandleUpdateNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		EmailEnabled       bool `json:"email_enabled"`
		PushEnabled        bool `json:"push_enabled"`
		SMSEnabled         bool `json:"sms_enabled"`
		SecurityAlerts     bool `json:"security_alerts"`
		TransactionUpdates bool `json:"transaction_updates"`
		PerformanceMetrics bool `json:"performance_metrics"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Error("Invalid request data: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid request data"})
		return
	}

	settings := notifications.NewNotificationSettings()
	settings.EmailEnabled = requestData.EmailEnabled
	settings.PushEnabled = requestData.PushEnabled
	settings.SMSEnabled = requestData.SMSEnabled
	settings.SecurityAlerts = requestData.SecurityAlerts
	settings.TransactionUpdates = requestData.TransactionUpdates
	settings.PerformanceMetrics = requestData.PerformanceMetrics

	if err := settings.ValidateSettings(); err != nil {
		log.Error("Invalid notification settings: ", err)
		respondWithJSON(w, http.StatusBadRequest, APIResponse{Status: "error", Message: "Invalid notification settings"})
		return
	}

	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "Notification settings updated successfully"})
}

// HandleConnectWebSocket handles establishing a WebSocket connection for real-time notifications
func HandleConnectWebSocket(w http.ResponseWriter, r *http.Request) {
	nm := notifications.NewNotificationManager()
	if err := nm.Connect("ws://notification-server-url"); err != nil {
		log.Error("Failed to connect to WebSocket: ", err)
		respondWithJSON(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: "Failed to connect to WebSocket"})
		return
	}

	go nm.ListenForNotifications()
	respondWithJSON(w, http.StatusOK, APIResponse{Status: "success", Message: "WebSocket connection established"})
}

// Set up the API routes
func SetupRoutes(router *mux.Router) {
	router.HandleFunc("/api/add_alert", HandleAddAlert).Methods("POST")
	router.HandleFunc("/api/list_alerts", HandleListAlerts).Methods("GET")
	router.HandleFunc("/api/handle_alert/{id}", HandleHandleAlert).Methods("POST")
	router.HandleFunc("/api/send_notification", HandleSendNotification).Methods("POST")
	router.HandleFunc("/api/update_notification_settings", HandleUpdateNotificationSettings).Methods("POST")
	router.HandleFunc("/api/connect_websocket", HandleConnectWebSocket).Methods("GET")
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, status int, payload APIResponse) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}
