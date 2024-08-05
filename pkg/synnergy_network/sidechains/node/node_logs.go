// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including logging capabilities for real-world use.
package node

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel represents the level of logging.
type LogLevel int

const (
	// Debug level for debugging information.
	Debug LogLevel = iota
	// Info level for informational messages.
	Info
	// Warning level for warning messages.
	Warning
	// Error level for error messages.
	Error
)

// LogEntry represents a log entry.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     LogLevel  `json:"level"`
	Message   string    `json:"message"`
	NodeID    string    `json:"node_id"`
}

// NodeLogger represents the logger for a node.
type NodeLogger struct {
	NodeID string
	mutex  sync.Mutex
	logs   []LogEntry
	file   *os.File
}

// NewNodeLogger creates a new NodeLogger instance for the specified node.
func NewNodeLogger(nodeID string, logDir string) (*NodeLogger, error) {
	filePath := filepath.Join(logDir, fmt.Sprintf("%s.log", nodeID))
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &NodeLogger{
		NodeID: nodeID,
		logs:   []LogEntry{},
		file:   file,
	}, nil
}

// Log logs a message with the specified level.
func (nl *NodeLogger) Log(level LogLevel, message string) {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		NodeID:    nl.NodeID,
	}

	nl.logs = append(nl.logs, entry)
	nl.writeToFile(entry)
}

// writeToFile writes a log entry to the log file.
func (nl *NodeLogger) writeToFile(entry LogEntry) {
	logData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("failed to marshal log entry: %v", err)
		return
	}

	if _, err := nl.file.WriteString(string(logData) + "\n"); err != nil {
		log.Printf("failed to write log entry to file: %v", err)
	}
}

// GetLogs returns all logs for the node.
func (nl *NodeLogger) GetLogs() []LogEntry {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	return nl.logs
}

// ClearLogs clears all logs for the node.
func (nl *NodeLogger) ClearLogs() {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	nl.logs = []LogEntry{}
	nl.file.Truncate(0)
	nl.file.Seek(0, 0)
}

// Close closes the log file.
func (nl *NodeLogger) Close() error {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	if err := nl.file.Close(); err != nil {
		return fmt.Errorf("failed to close log file: %w", err)
	}

	return nil
}

// MonitoringAPI represents the monitoring API for node interactions including log retrieval.
type MonitoringAPI struct {
	Node   *Node
	Server *http.Server
}

// NewMonitoringAPI creates a new MonitoringAPI instance.
func NewMonitoringAPI(node *Node) *MonitoringAPI {
	return &MonitoringAPI{Node: node}
}

// StartMonitoringAPI starts the monitoring API server for the node.
func (api *MonitoringAPI) StartMonitoringAPI(port int) error {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", api.MetricsHandler)
	mux.HandleFunc("/peers", api.PeersHandler)
	mux.HandleFunc("/addPeer", api.AddPeerHandler)
	mux.HandleFunc("/removePeer", api.RemovePeerHandler)
	mux.HandleFunc("/logs", api.LogsHandler)
	mux.HandleFunc("/clearLogs", api.ClearLogsHandler)

	api.Server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if err := api.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting Monitoring API server: %v\n", err)
		}
	}()
	log.Printf("Monitoring API server started on port %d\n", port)
	return nil
}

// StopMonitoringAPI stops the monitoring API server for the node.
func (api *MonitoringAPI) StopMonitoringAPI() error {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	if api.Server != nil {
		if err := api.Server.Close(); err != nil {
			return err
		}
		log.Println("Monitoring API server stopped")
	}
	return nil
}

// LogsHandler handles requests for retrieving node logs.
func (api *MonitoringAPI) LogsHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	logs := api.Node.Logger.GetLogs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// ClearLogsHandler handles requests for clearing node logs.
func (api *MonitoringAPI) ClearLogsHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	api.Node.Logger.ClearLogs()
	w.WriteHeader(http.StatusOK)
}

// Node represents a blockchain node with logging capabilities.
type Node struct {
	ID               string
	Address          string
	Peers            map[string]*Peer
	mutex            sync.Mutex
	MonitoringAPI    *MonitoringAPI
	Metrics          Metrics
	Logger           *NodeLogger
}

// NewNode creates a new Node instance with specified parameters.
func NewNode(id, address, logDir string) (*Node, error) {
	logger, err := NewNodeLogger(id, logDir)
	if err != nil {
		return nil, err
	}

	node := &Node{
		ID:            id,
		Address:       address,
		Peers:         make(map[string]*Peer),
		MonitoringAPI: NewMonitoringAPI(nil),
		Metrics:       Metrics{},
		Logger:        logger,
	}

	node.MonitoringAPI.Node = node
	return node, nil
}

// UpdateMetrics updates the metrics of the node.
func (n *Node) UpdateMetrics(cpu, memory, disk, network float64) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.Metrics = Metrics{
		CPUUsage:    cpu,
		MemoryUsage: memory,
		DiskUsage:   disk,
		NetworkIO:   network,
	}

	n.Logger.Log(Info, "Metrics updated")
}

// MonitorMetrics monitors and updates the node metrics periodically.
func (n *Node) MonitorMetrics(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// Simulate metric collection
		cpu := getCPUUsage()
		memory := getMemoryUsage()
		disk := getDiskUsage()
		network := getNetworkIO()

		n.UpdateMetrics(cpu, memory, disk, network)
	}
}

// Simulated functions for metric collection (replace with real implementations)
func getCPUUsage() float64    { return 30.5 }
func getMemoryUsage() float64 { return 40.2 }
func getDiskUsage() float64   { return 50.8 }
func getNetworkIO() float64   { return 60.1 }

// Example usage:
// func main() {
// 	logDir := "./logs"
// 	node, err := NewNode("node-1", "address-1", logDir)
// 	if err != nil {
// 		log.Fatalf("Failed to create node: %v", err)
// 	}
// 	go node.MonitorMetrics(10 * time.Second)
// 	node.MonitoringAPI.StartMonitoringAPI(8080)
// 	defer node.MonitoringAPI.StopMonitoringAPI()
// }
