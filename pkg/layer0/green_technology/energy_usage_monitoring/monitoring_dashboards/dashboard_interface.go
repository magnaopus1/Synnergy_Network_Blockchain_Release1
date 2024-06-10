package monitoring_dashboards

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/energy_usage_monitoring"
	"github.com/synthron_blockchain_final/pkg/utils"
)

// EnergyData represents the structure of the energy consumption data.
type EnergyData struct {
	NodeID      string    `json:"node_id"`
	Timestamp   time.Time `json:"timestamp"`
	Usage       float64   `json:"usage"`
	Temperature float64   `json:"temperature"`
	Humidity    float64   `json:"humidity"`
}

// Dashboard represents the energy usage monitoring dashboard.
type Dashboard struct {
	mu        sync.Mutex
	data      []EnergyData
	dataMap   map[string][]EnergyData
	predictor *energy_usage_monitoring.EnergyUsagePredictor
}

// NewDashboard creates a new instance of Dashboard.
func NewDashboard(modelFilePath string) *Dashboard {
	predictor := energy_usage_monitoring.NewEnergyUsagePredictor(modelFilePath)
	return &Dashboard{
		data:      []EnergyData{},
		dataMap:   make(map[string][]EnergyData),
		predictor: predictor,
	}
}

// AddEnergyData adds new energy consumption data to the dashboard.
func (d *Dashboard) AddEnergyData(data EnergyData) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.data = append(d.data, data)
	d.dataMap[data.NodeID] = append(d.dataMap[data.NodeID], data)

	record := energy_usage_monitoring.EnergyUsageRecord{
		Timestamp:   data.Timestamp,
		Usage:       data.Usage,
		Temperature: data.Temperature,
		Humidity:    data.Humidity,
	}
	d.predictor.AddRecord(record)
}

// TrainModel trains the energy usage predictor model.
func (d *Dashboard) TrainModel() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.predictor.TrainModel()
}

// LoadModel loads the trained energy usage predictor model.
func (d *Dashboard) LoadModel() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.predictor.LoadModel()
}

// SaveModel saves the trained energy usage predictor model.
func (d *Dashboard) SaveModel() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.predictor.SaveModel()
}

// GetPredictedUsage predicts the energy usage based on current conditions.
func (d *Dashboard) GetPredictedUsage(currentTemperature, currentHumidity float64) (float64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.predictor.PredictUsage(currentTemperature, currentHumidity)
}

// ServeHTTP serves the dashboard data via HTTP.
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		d.handleGet(w, r)
	case http.MethodPost:
		d.handlePost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Dashboard) handleGet(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID != "" {
		data, ok := d.dataMap[nodeID]
		if !ok {
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(data)
		return
	}
	json.NewEncoder(w).Encode(d.data)
}

func (d *Dashboard) handlePost(w http.ResponseWriter, r *http.Request) {
	var data EnergyData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	d.AddEnergyData(data)
	w.WriteHeader(http.StatusCreated)
}

func (d *Dashboard) ServeDashboard(port int) {
	http.Handle("/dashboard", d)
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Serving energy usage dashboard on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Printf("Failed to serve dashboard: %v\n", err)
	}
}

// Example usage
func main() {
	modelFilePath := "energy_usage_model.json"
	dashboard := NewDashboard(modelFilePath)

	// Load existing model
	if err := dashboard.LoadModel(); err != nil {
		fmt.Println("Error loading model:", err)
	}

	// Train model with new data
	if err := dashboard.TrainModel(); err != nil {
		fmt.Println("Error training model:", err)
	}

	// Save model
	if err := dashboard.SaveModel(); err != nil {
		fmt.Println("Error saving model:", err)
	}

	// Serve dashboard
	go dashboard.ServeDashboard(8080)

	// Add some dummy data
	dashboard.AddEnergyData(EnergyData{
		NodeID:      "node1",
		Timestamp:   time.Now(),
		Usage:       120.5,
		Temperature: 22.5,
		Humidity:    55.0,
	})

	// Simulate a prediction request
	predictedUsage, err := dashboard.GetPredictedUsage(25.0, 60.0)
	if err != nil {
		fmt.Println("Error predicting usage:", err)
	} else {
		fmt.Printf("Predicted energy usage: %.2f\n", predictedUsage)
	}

	// Keep the main function running
	select {}
}
