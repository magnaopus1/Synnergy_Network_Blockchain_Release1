package monitoring_dashboards

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/energy_usage_monitoring"
	"github.com/synthron_blockchain_final/pkg/utils"
)

// AggregatedData represents the aggregated structure of the energy consumption data.
type AggregatedData struct {
	TotalUsage     float64   `json:"total_usage"`
	AverageUsage   float64   `json:"average_usage"`
	PeakUsage      float64   `json:"peak_usage"`
	UsageByNode    map[string]float64 `json:"usage_by_node"`
	Timestamp      time.Time `json:"timestamp"`
}

// DataAggregator represents the energy usage data aggregator.
type DataAggregator struct {
	mu             sync.Mutex
	rawData        []EnergyData
	aggregatedData AggregatedData
}

// NewDataAggregator creates a new instance of DataAggregator.
func NewDataAggregator() *DataAggregator {
	return &DataAggregator{
		rawData:     []EnergyData{},
		aggregatedData: AggregatedData{
			UsageByNode: make(map[string]float64),
		},
	}
}

// AddRawData adds new raw energy consumption data to the aggregator.
func (da *DataAggregator) AddRawData(data EnergyData) {
	da.mu.Lock()
	defer da.mu.Unlock()

	da.rawData = append(da.rawData, data)
	da.aggregatedData.TotalUsage += data.Usage
	da.aggregatedData.UsageByNode[data.NodeID] += data.Usage
	if data.Usage > da.aggregatedData.PeakUsage {
		da.aggregatedData.PeakUsage = data.Usage
	}
	da.aggregatedData.AverageUsage = da.aggregatedData.TotalUsage / float64(len(da.rawData))
	da.aggregatedData.Timestamp = time.Now()
}

// GetAggregatedData returns the aggregated energy consumption data.
func (da *DataAggregator) GetAggregatedData() AggregatedData {
	da.mu.Lock()
	defer da.mu.Unlock()
	return da.aggregatedData
}

// ServeHTTP serves the aggregated data via HTTP.
func (da *DataAggregator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	da.mu.Lock()
	defer da.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		da.handleGet(w, r)
	case http.MethodPost:
		da.handlePost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (da *DataAggregator) handleGet(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(da.aggregatedData)
}

func (da *DataAggregator) handlePost(w http.ResponseWriter, r *http.Request) {
	var data EnergyData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	da.AddRawData(data)
	w.WriteHeader(http.StatusCreated)
}

// Example usage
func main() {
	aggregator := NewDataAggregator()

	// Add some dummy data
	aggregator.AddRawData(EnergyData{
		NodeID:      "node1",
		Timestamp:   time.Now(),
		Usage:       120.5,
		Temperature: 22.5,
		Humidity:    55.0,
	})

	// Serve aggregated data
	go func() {
		http.Handle("/aggregated", aggregator)
		addr := ":8081"
		fmt.Printf("Serving aggregated data on %s\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Printf("Failed to serve aggregated data: %v\n", err)
		}
	}()

	// Keep the main function running
	select {}
}
