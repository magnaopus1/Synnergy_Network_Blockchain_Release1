package decentralized_monitoring_network

import (
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/utils/encryption_utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/utils/logging_utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/utils/monitoring_utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/utils/signature_utils"
)

// MonitoringData represents the data structure for monitoring information.
type MonitoringData struct {
	NodeID        string    `json:"node_id"`
	Timestamp     time.Time `json:"timestamp"`
	CPUUsage      float64   `json:"cpu_usage"`
	MemoryUsage   float64   `json:"memory_usage"`
	NetworkLatency float64  `json:"network_latency"`
	Signature     string    `json:"signature"`
}

// DistributedMonitoringProtocol manages decentralized monitoring.
type DistributedMonitoringProtocol struct {
	mu               sync.Mutex
	peerConnections  map[string]net.Conn
	monitoringData   map[string]MonitoringData
	alertSubscribers []chan MonitoringData
}

// NewDistributedMonitoringProtocol initializes a new DistributedMonitoringProtocol.
func NewDistributedMonitoringProtocol() *DistributedMonitoringProtocol {
	return &DistributedMonitoringProtocol{
		peerConnections:  make(map[string]net.Conn),
		monitoringData:   make(map[string]MonitoringData),
		alertSubscribers: make([]chan MonitoringData, 0),
	}
}

// AddPeer adds a new peer to the monitoring network.
func (dmp *DistributedMonitoringProtocol) AddPeer(nodeID string, conn net.Conn) {
	dmp.mu.Lock()
	defer dmp.mu.Unlock()
	dmp.peerConnections[nodeID] = conn
	logging_utils.LogInfo("Added peer: " + nodeID)
}

// RemovePeer removes a peer from the monitoring network.
func (dmp *DistributedMonitoringProtocol) RemovePeer(nodeID string) {
	dmp.mu.Lock()
	defer dmp.mu.Unlock()
	delete(dmp.peerConnections, nodeID)
	logging_utils.LogInfo("Removed peer: " + nodeID)
}

// CollectData collects monitoring data from peers.
func (dmp *DistributedMonitoringProtocol) CollectData(nodeID string, data MonitoringData) {
	dmp.mu.Lock()
	defer dmp.mu.Unlock()
	// Verify the signature of the received data.
	if !signature_utils.VerifySignature(data.Signature, data) {
		logging_utils.LogWarning("Invalid signature for data from node: " + nodeID)
		return
	}

	dmp.monitoringData[nodeID] = data
	logging_utils.LogInfo("Collected data from node: " + nodeID)
	dmp.notifySubscribers(data)
}

// GetMonitoringData returns the current monitoring data for all peers.
func (dmp *DistributedMonitoringProtocol) GetMonitoringData() map[string]MonitoringData {
	dmp.mu.Lock()
	defer dmp.mu.Unlock()
	return dmp.monitoringData
}

// SubscribeToAlerts subscribes to monitoring data alerts.
func (dmp *DistributedMonitoringProtocol) SubscribeToAlerts(subscriber chan MonitoringData) {
	dmp.mu.Lock()
	defer dmp.mu.Unlock()
	dmp.alertSubscribers = append(dmp.alertSubscribers, subscriber)
}

// notifySubscribers notifies all subscribers of new monitoring data.
func (dmp *DistributedMonitoringProtocol) notifySubscribers(data MonitoringData) {
	for _, subscriber := range dmp.alertSubscribers {
		select {
		case subscriber <- data:
		default:
			logging_utils.LogWarning("Dropping alert notification to a subscriber")
		}
	}
}

// BroadcastData broadcasts monitoring data to all peers.
func (dmp *DistributedMonitoringProtocol) BroadcastData(data MonitoringData) {
	dmp.mu.Lock()
	defer dmp.mu.Unlock()
	encryptedData, err := encryption_utils.EncryptData(data)
	if err != nil {
		logging_utils.LogError("Failed to encrypt data for broadcasting: " + err.Error())
		return
	}

	for nodeID, conn := range dmp.peerConnections {
		go func(conn net.Conn, nodeID string) {
			encoder := json.NewEncoder(conn)
			err := encoder.Encode(encryptedData)
			if err != nil {
				logging_utils.LogError("Failed to send data to peer " + nodeID + ": " + err.Error())
			}
		}(conn, nodeID)
	}
}

// StartMonitoring starts the decentralized monitoring process.
func (dmp *DistributedMonitoringProtocol) StartMonitoring() {
	go func() {
		for {
			dmp.mu.Lock()
			for nodeID, data := range dmp.monitoringData {
				if time.Since(data.Timestamp) > 5*time.Minute {
					logging_utils.LogWarning("No recent data from node: " + nodeID)
					dmp.RemovePeer(nodeID)
				}
			}
			dmp.mu.Unlock()
			time.Sleep(1 * time.Minute)
		}
	}()
}

// MonitorLocalNode monitors the local node's performance and broadcasts the data.
func (dmp *DistributedMonitoringProtocol) MonitorLocalNode(nodeID string) {
	go func() {
		for {
			data := MonitoringData{
				NodeID:        nodeID,
				Timestamp:     time.Now(),
				CPUUsage:      monitoring_utils.GetCPUUsage(),
				MemoryUsage:   monitoring_utils.GetMemoryUsage(),
				NetworkLatency: monitoring_utils.GetNetworkLatency(),
			}
			data.Signature = signature_utils.GenerateSignature(data)
			dmp.CollectData(nodeID, data)
			dmp.BroadcastData(data)
			time.Sleep(30 * time.Second)
		}
	}()
}
