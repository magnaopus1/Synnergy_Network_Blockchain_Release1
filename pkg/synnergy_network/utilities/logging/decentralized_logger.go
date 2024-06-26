package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DecentralizedLogger is a logger that distributes log data across multiple nodes
type DecentralizedLogger struct {
	nodes          []string
	logEntries     []LogEntry
	mutex          sync.Mutex
	maxEntries     int
	aggregationMgr *AggregationManager
}

// LogEntry represents a log entry with contextual information
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Context   string    `json:"context"`
}

// AggregationManager manages the aggregation of logs in a decentralized system
type AggregationManager struct {
	storagePath string
}

// NewDecentralizedLogger initializes a new DecentralizedLogger instance
func NewDecentralizedLogger(nodes []string, maxEntries int, storagePath string) *DecentralizedLogger {
	return &DecentralizedLogger{
		nodes:          nodes,
		maxEntries:     maxEntries,
		aggregationMgr: NewAggregationManager(storagePath),
	}
}

// AddLogEntry adds a new log entry to the decentralized logger
func (dl *DecentralizedLogger) AddLogEntry(level, message, context string) {
	dl.mutex.Lock()
	defer dl.mutex.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Context:   context,
	}
	dl.logEntries = append(dl.logEntries, entry)
	logrus.Infof("Log entry added: %s - %s", level, message)

	if len(dl.logEntries) >= dl.maxEntries {
		dl.distributeLogs()
	}
}

// distributeLogs distributes log entries across the nodes
func (dl *DecentralizedLogger) distributeLogs() {
	logrus.Info("Distributing logs to nodes")

	for _, node := range dl.nodes {
		for _, entry := range dl.logEntries {
			// Simulate log distribution
			logrus.Infof("Sending log to node %s: %s", node, entry.Message)
		}
	}

	// Clear log entries after distribution
	dl.logEntries = []LogEntry{}
}

// NewAggregationManager initializes a new AggregationManager
func NewAggregationManager(storagePath string) *AggregationManager {
	return &AggregationManager{storagePath: storagePath}
}

// AggregateLogs aggregates logs from all nodes
func (am *AggregationManager) AggregateLogs(logEntries []LogEntry) error {
	logrus.Info("Aggregating logs")

	data, err := json.Marshal(logEntries)
	if err != nil {
		return fmt.Errorf("failed to marshal log entries: %v", err)
	}

	file, err := os.Create(fmt.Sprintf("%s/aggregated_logs_%d.json", am.storagePath, time.Now().Unix()))
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write log data to file: %v", err)
	}

	return nil
}

// Example of usage
func main() {
	nodes := []string{"node1", "node2", "node3"}
	logger := NewDecentralizedLogger(nodes, 10, "./logs")

	// Add log entries
	logger.AddLogEntry("INFO", "Blockchain node started", "node1")
	logger.AddLogEntry("ERROR", "Failed to connect to peer", "node1")
	// Add more entries to simulate activity...

	// Aggregate logs
	entries := []LogEntry{
		{Timestamp: time.Now(), Level: "INFO", Message: "Node started", Context: "node1"},
		{Timestamp: time.Now(), Level: "ERROR", Message: "Connection failed", Context: "node2"},
	}
	err := logger.aggregationMgr.AggregateLogs(entries)
	if err != nil {
		logrus.Fatalf("Failed to aggregate logs: %v", err)
	}
}
