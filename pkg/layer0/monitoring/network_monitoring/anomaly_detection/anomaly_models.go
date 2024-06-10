package anomaly_detection

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/gonum/stat"
	"gonum.org/v1/gonum/mat"
)

// AnomalyModel represents an anomaly detection model
type AnomalyModel interface {
	Train(data []NetworkData) error
	Predict(data NetworkData) (float64, error)
}

// MovingAverageModel is a simple moving average anomaly detection model
type MovingAverageModel struct {
	windowSize int
	threshold  float64
	window     []float64
}

// NewMovingAverageModel creates a new MovingAverageModel
func NewMovingAverageModel(windowSize int, threshold float64) *MovingAverageModel {
	return &MovingAverageModel{
		windowSize: windowSize,
		threshold:  threshold,
		window:     make([]float64, 0, windowSize),
	}
}

// Train trains the model with historical data
func (m *MovingAverageModel) Train(data []NetworkData) error {
	for _, d := range data {
		if len(m.window) < m.windowSize {
			m.window = append(m.window, d.Value)
		} else {
			m.window = append(m.window[1:], d.Value)
		}
	}
	return nil
}

// Predict predicts the anomaly score for a new data point
func (m *MovingAverageModel) Predict(data NetworkData) (float64, error) {
	if len(m.window) < m.windowSize {
		return 0, errors.New("insufficient data to make a prediction")
	}
	mean := stat.Mean(m.window, nil)
	deviation := math.Abs(data.Value - mean)
	anomalyScore := deviation / mean
	if anomalyScore > m.threshold {
		return anomalyScore, nil
	}
	return 0, nil
}

// ZScoreModel represents a Z-Score based anomaly detection model
type ZScoreModel struct {
	mean     float64
	stdDev   float64
	threshold float64
}

// NewZScoreModel creates a new ZScoreModel
func NewZScoreModel(threshold float64) *ZScoreModel {
	return &ZScoreModel{
		threshold: threshold,
	}
}

// Train trains the model with historical data
func (m *ZScoreModel) Train(data []NetworkData) error {
	values := make([]float64, len(data))
	for i, d := range data {
		values[i] = d.Value
	}
	m.mean = stat.Mean(values, nil)
	m.stdDev = stat.StdDev(values, nil)
	return nil
}

// Predict predicts the anomaly score for a new data point
func (m *ZScoreModel) Predict(data NetworkData) (float64, error) {
	if m.stdDev == 0 {
		return 0, errors.New("standard deviation is zero, can't calculate Z-Score")
	}
	zScore := (data.Value - m.mean) / m.stdDev
	if math.Abs(zScore) > m.threshold {
		return math.Abs(zScore), nil
	}
	return 0, nil
}

// IsolationForestModel represents an isolation forest based anomaly detection model
type IsolationForestModel struct {
	trees     []*IsolationTree
	nTrees    int
	sampleSize int
	threshold  float64
}

// NewIsolationForestModel creates a new IsolationForestModel
func NewIsolationForestModel(nTrees, sampleSize int, threshold float64) *IsolationForestModel {
	return &IsolationForestModel{
		nTrees:    nTrees,
		sampleSize: sampleSize,
		threshold:  threshold,
	}
}

// Train trains the model with historical data
func (m *IsolationForestModel) Train(data []NetworkData) error {
	// Implement the training logic for Isolation Forest
	// For simplicity, this is a placeholder
	return nil
}

// Predict predicts the anomaly score for a new data point
func (m *IsolationForestModel) Predict(data NetworkData) (float64, error) {
	// Implement the prediction logic for Isolation Forest
	// For simplicity, this is a placeholder
	return 0, nil
}

// IsolationTree represents a single tree in the isolation forest
type IsolationTree struct {
	// Implement the structure of an Isolation Tree
}

// AnomalyDetectionSystem handles anomaly detection within the blockchain network
type AnomalyDetectionSystem struct {
	models     map[string]AnomalyModel
	dataChannel chan NetworkData
	anomalyLogs []AnomalyLog
}

// NewAnomalyDetectionSystem creates a new anomaly detection system
func NewAnomalyDetectionSystem() *AnomalyDetectionSystem {
	return &AnomalyDetectionSystem{
		models:     make(map[string]AnomalyModel),
		dataChannel: make(chan NetworkData),
		anomalyLogs: make([]AnomalyLog, 0),
	}
}

// RegisterModel registers an anomaly detection model for a specific metric
func (ads *AnomalyDetectionSystem) RegisterModel(metric string, model AnomalyModel) {
	ads.models[metric] = model
}

// CollectData collects network data from a node
func (ads *AnomalyDetectionSystem) CollectData(data NetworkData) {
	ads.dataChannel <- data
}

// StartMonitoring starts the monitoring process
func (ads *AnomalyDetectionSystem) StartMonitoring() {
	go func() {
		for data := range ads.dataChannel {
			model, exists := ads.models[data.Metric]
			if !exists {
				log.Printf("No model registered for metric: %s", data.Metric)
				continue
			}
			score, err := model.Predict(data)
			if err != nil {
				log.Printf("Error predicting anomaly score: %v", err)
				continue
			}
			if score > 0 {
				ads.logAnomaly(data, score)
			}
		}
	}()
}

// logAnomaly logs detected anomalies
func (ads *AnomalyDetectionSystem) logAnomaly(data NetworkData, score float64) {
	ads.anomalyLogs = append(ads.anomalyLogs, AnomalyLog{
		NodeID:    data.NodeID,
		Timestamp: data.Timestamp,
		Metric:    data.Metric,
		Value:     data.Value,
		Score:     score,
	})
	log.Printf("Anomaly detected: NodeID=%s, Metric=%s, Value=%.2f, Score=%.2f\n", data.NodeID, data.Metric, data.Value, score)
}

// AnomalyLog stores information about detected anomalies
type AnomalyLog struct {
	NodeID    string
	Timestamp time.Time
	Metric    string
	Value     float64
	Score     float64
}

// NetworkData represents data collected from the network
type NetworkData struct {
	NodeID       string
	Timestamp    time.Time
	Metric       string
	Value        float64
}

// SaveAnomalyLogs saves the anomaly logs to a JSON file
func (ads *AnomalyDetectionSystem) SaveAnomalyLogs(filename string) error {
	data, err := json.MarshalIndent(ads.anomalyLogs, "", "  ")
	if err != nil {
		return err
	}
	return utils.WriteToFile(filename, data)
}

// LoadAnomalyLogs loads the anomaly logs from a JSON file
func (ads *AnomalyDetectionSystem) LoadAnomalyLogs(filename string) error {
	data, err := utils.ReadFromFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ads.anomalyLogs)
}

// Utility functions for reading and writing files
package utils

import (
	"io/ioutil"
	"os"
)

// WriteToFile writes data to a file
func WriteToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// ReadFromFile reads data from a file
func ReadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
