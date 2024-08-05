package predictive_maintenance

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/synnergy_network_blockchain/pkg/synnergy_network/core/utils"
)

// RealTimeMonitoringService represents the service responsible for real-time monitoring
type RealTimeMonitoringService struct {
    sync.Mutex
    monitoringData map[string]interface{}
    alertThreshold float64
    alertChannel   chan string
    clients        []chan interface{}
}

// NewRealTimeMonitoringService creates a new instance of RealTimeMonitoringService
func NewRealTimeMonitoringService(threshold float64) *RealTimeMonitoringService {
    return &RealTimeMonitoringService{
        monitoringData: make(map[string]interface{}),
        alertThreshold: threshold,
        alertChannel:   make(chan string),
        clients:        []chan interface{}{},
    }
}

// StartMonitoring initiates the real-time monitoring process
func (service *RealTimeMonitoringService) StartMonitoring() {
    go func() {
        for {
            service.collectData()
            time.Sleep(1 * time.Minute)
        }
    }()
}

// collectData collects real-time data from various sources
func (service *RealTimeMonitoringService) collectData() {
    // Mock data collection from sensors, logs, etc.
    data := map[string]interface{}{
        "cpu_usage":    75.5,
        "memory_usage": 60.3,
        "disk_usage":   80.1,
    }
    service.Lock()
    service.monitoringData = data
    service.Unlock()

    service.checkThresholds()
    service.notifyClients()
}

// checkThresholds checks if any collected data exceeds the alert threshold
func (service *RealTimeMonitoringService) checkThresholds() {
    service.Lock()
    defer service.Unlock()

    for key, value := range service.monitoringData {
        if val, ok := value.(float64); ok && val > service.alertThreshold {
            alert := fmt.Sprintf("Alert: %s has exceeded the threshold with value %.2f", key, val)
            service.alertChannel <- alert
            log.Println(alert)
        }
    }
}

// notifyClients sends the latest monitoring data to connected clients
func (service *RealTimeMonitoringService) notifyClients() {
    service.Lock()
    defer service.Unlock()

    for _, client := range service.clients {
        client <- service.monitoringData
    }
}

// AddClient adds a new client to receive real-time monitoring data
func (service *RealTimeMonitoringService) AddClient(client chan interface{}) {
    service.Lock()
    service.clients = append(service.clients, client)
    service.Unlock()
}

// GetMonitoringData returns the current monitoring data
func (service *RealTimeMonitoringService) GetMonitoringData() map[string]interface{} {
    service.Lock()
    defer service.Unlock()
    return service.monitoringData
}

// HandleAlerts handles alerts by sending notifications to admins
func (service *RealTimeMonitoringService) HandleAlerts() {
    go func() {
        for {
            select {
            case alert := <-service.alertChannel:
                // Mock sending email alert to admin
                utils.SendEmail("admin@synnergy.com", "Real-Time Monitoring Alert", alert)
            }
        }
    }()
}

// HTTP Handler Functions

// monitoringDataHandler handles the HTTP request for real-time monitoring data
func (service *RealTimeMonitoringService) monitoringDataHandler(w http.ResponseWriter, r *http.Request) {
    data := service.GetMonitoringData()
    json.NewEncoder(w).Encode(data)
}

// alertHandler handles the HTTP request for real-time alerts
func (service *RealTimeMonitoringService) alertHandler(w http.ResponseWriter, r *http.Request) {
    alert := <-service.alertChannel
    fmt.Fprintf(w, "Alert: %s", alert)
}

// StartServer starts the HTTP server for real-time monitoring
func (service *RealTimeMonitoringService) StartServer(port string) {
    http.HandleFunc("/monitoring-data", service.monitoringDataHandler)
    http.HandleFunc("/alert", service.alertHandler)
    log.Printf("Starting server on port %s\n", port)
    log.Fatal(http.ListenAndServe(port, nil))
}

func main() {
    monitoringService := NewRealTimeMonitoringService(70.0)
    monitoringService.StartMonitoring()
    monitoringService.HandleAlerts()
    monitoringService.StartServer(":8080")
}
