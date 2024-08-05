package ai_driven_analytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/core/monitoring"
	"github.com/synnergy_network/utils"
)

// PredictiveResourceAllocation struct for managing predictive resource allocation
type PredictiveResourceAllocation struct {
	mu            sync.Mutex
	models        []PredictiveModel
	resourceData  map[string]ResourceMetrics
	alertSystem   *monitoring.AlertSystem
	blockchain    *blockchain.Blockchain
	modelAccuracy float64
}

// ResourceMetrics stores metrics for resource usage
type ResourceMetrics struct {
	CPUUsage     float64
	MemoryUsage  float64
	DiskUsage    float64
	NetworkUsage float64
	Timestamp    time.Time
}

// PredictiveModel interface for predictive models
type PredictiveModel interface {
	Train(data []ResourceMetrics) error
	Predict(current ResourceMetrics) (ResourceMetrics, error)
}

// NewPredictiveResourceAllocation creates a new PredictiveResourceAllocation
func NewPredictiveResourceAllocation(alertSystem *monitoring.AlertSystem, blockchain *blockchain.Blockchain) *PredictiveResourceAllocation {
	return &PredictiveResourceAllocation{
		models:       []PredictiveModel{},
		resourceData: make(map[string]ResourceMetrics),
		alertSystem:  alertSystem,
		blockchain:   blockchain,
	}
}

// AddModel adds a predictive model
func (pra *PredictiveResourceAllocation) AddModel(model PredictiveModel) {
	pra.mu.Lock()
	defer pra.mu.Unlock()
	pra.models = append(pra.models, model)
}

// UpdateMetrics updates the resource metrics
func (pra *PredictiveResourceAllocation) UpdateMetrics(nodeID string, metrics ResourceMetrics) {
	pra.mu.Lock()
	defer pra.mu.Unlock()
	pra.resourceData[nodeID] = metrics
}

// TrainModels trains all predictive models
func (pra *PredictiveResourceAllocation) TrainModels() error {
	pra.mu.Lock()
	defer pra.mu.Unlock()

	var data []ResourceMetrics
	for _, metrics := range pra.resourceData {
		data = append(data, metrics)
	}

	for _, model := range pra.models {
		if err := model.Train(data); err != nil {
			return err
		}
	}
	return nil
}

// PredictResources predicts future resource usage
func (pra *PredictiveResourceAllocation) PredictResources(nodeID string) (ResourceMetrics, error) {
	pra.mu.Lock()
	defer pra.mu.Unlock()

	metrics, exists := pra.resourceData[nodeID]
	if !exists {
		return ResourceMetrics{}, errors.New("node metrics not found")
	}

	var predictions []ResourceMetrics
	for _, model := range pra.models {
		prediction, err := model.Predict(metrics)
		if err != nil {
			return ResourceMetrics{}, err
		}
		predictions = append(predictions, prediction)
	}

	// Aggregate predictions
	avgPrediction := pra.aggregatePredictions(predictions)
	return avgPrediction, nil
}

// aggregatePredictions aggregates multiple model predictions
func (pra *PredictiveResourceAllocation) aggregatePredictions(predictions []ResourceMetrics) ResourceMetrics {
	totalCPU := 0.0
	totalMemory := 0.0
	totalDisk := 0.0
	totalNetwork := 0.0

	for _, prediction := range predictions {
		totalCPU += prediction.CPUUsage
		totalMemory += prediction.MemoryUsage
		totalDisk += prediction.DiskUsage
		totalNetwork += prediction.NetworkUsage
	}

	count := float64(len(predictions))
	return ResourceMetrics{
		CPUUsage:     totalCPU / count,
		MemoryUsage:  totalMemory / count,
		DiskUsage:    totalDisk / count,
		NetworkUsage: totalNetwork / count,
		Timestamp:    time.Now(),
	}
}

// MonitorResources monitors and optimizes resource allocation
func (pra *PredictiveResourceAllocation) MonitorResources() {
	for {
		pra.mu.Lock()
		for nodeID, metrics := range pra.resourceData {
			prediction, err := pra.PredictResources(nodeID)
			if err != nil {
				log.Printf("Prediction error for node %s: %v", nodeID, err)
				continue
			}

			// Generate alert if predicted usage exceeds threshold
			if prediction.CPUUsage > 80.0 || prediction.MemoryUsage > 80.0 || prediction.DiskUsage > 80.0 || prediction.NetworkUsage > 80.0 {
				alert := monitoring.Alert{
					NodeID:    nodeID,
					Timestamp: time.Now(),
					Message:   fmt.Sprintf("High resource usage predicted: %+v", prediction),
					Severity:  monitoring.High,
				}
				pra.alertSystem.SendAlert(alert)
			}
		}
		pra.mu.Unlock()

		time.Sleep(10 * time.Minute)
	}
}

// SaveMetricsToBlockchain saves resource metrics to the blockchain
func (pra *PredictiveResourceAllocation) SaveMetricsToBlockchain() error {
	pra.mu.Lock()
	defer pra.mu.Unlock()

	data, err := json.Marshal(pra.resourceData)
	if err != nil {
		return err
	}

	transaction := blockchain.Transaction{
		Data: data,
	}

	return pra.blockchain.AddTransaction(transaction)
}

// PredictiveModelImplementation simple predictive model for demonstration
type PredictiveModelImplementation struct{}

// Train trains the predictive model
func (pm *PredictiveModelImplementation) Train(data []ResourceMetrics) error {
	// Implement training logic
	return nil
}

// Predict predicts future resource usage
func (pm *PredictiveModelImplementation) Predict(current ResourceMetrics) (ResourceMetrics, error) {
	// Implement prediction logic
	return ResourceMetrics{
		CPUUsage:     current.CPUUsage + rand.Float64()*10 - 5,
		MemoryUsage:  current.MemoryUsage + rand.Float64()*10 - 5,
		DiskUsage:    current.DiskUsage + rand.Float64()*10 - 5,
		NetworkUsage: current.NetworkUsage + rand.Float64()*10 - 5,
		Timestamp:    time.Now(),
	}, nil
}


