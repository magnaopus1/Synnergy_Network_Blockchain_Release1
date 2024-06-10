package logging

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gonum.org/v1/gonum/stat"
)

// AnomalyDetector manages anomaly detection in log entries
type AnomalyDetector struct {
	logEntries  []LogEntry
	mutex       sync.Mutex
	threshold   float64
	windowSize  int
	alertMethod func(string)
}

// LogEntry represents a log entry with contextual information
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Context   string    `json:"context"`
}

// NewAnomalyDetector initializes a new AnomalyDetector instance
func NewAnomalyDetector(threshold float64, windowSize int, alertMethod func(string)) *AnomalyDetector {
	return &AnomalyDetector{
		threshold:   threshold,
		windowSize:  windowSize,
		alertMethod: alertMethod,
	}
}

// AddLogEntry adds a new log entry to the anomaly detector
func (ad *AnomalyDetector) AddLogEntry(level, message, context string) {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Context:   context,
	}
	ad.logEntries = append(ad.logEntries, entry)
	log.Printf("Log entry added: %s - %s", level, message)

	if len(ad.logEntries) >= ad.windowSize {
		ad.detectAnomalies()
	}
}

// detectAnomalies detects anomalies in the log entries based on the configured threshold
func (ad *AnomalyDetector) detectAnomalies() {
	if len(ad.logEntries) < ad.windowSize {
		return
	}

	window := ad.logEntries[len(ad.logEntries)-ad.windowSize:]
	times := make([]float64, len(window))
	for i, entry := range window {
		times[i] = float64(entry.Timestamp.Unix())
	}

	mean, std := stat.MeanStdDev(times, nil)
	for _, entry := range window {
		z := (float64(entry.Timestamp.Unix()) - mean) / std
		if math.Abs(z) > ad.threshold {
			ad.alertMethod(fmt.Sprintf("Anomalous log entry detected: %s - %s", entry.Level, entry.Message))
		}
	}
}

// Example of usage
func main() {
	alertMethod := func(message string) {
		logrus.Warn(message)
	}

	// Initialize anomaly detector
	ad := NewAnomalyDetector(2.0, 10, alertMethod)

	// Add log entries
	ad.AddLogEntry("INFO", "Blockchain node started", "node1")
	ad.AddLogEntry("ERROR", "Failed to connect to peer", "node1")
	// Add more entries to simulate activity...
}
