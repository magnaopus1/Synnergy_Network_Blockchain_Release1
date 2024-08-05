package metrics

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/common"
)

type Metrics struct {
	NodeID        string
	MetricsServer string
	LogLevel      string
	mu            sync.Mutex
	data          map[string]interface{}
}

func (m *Metrics) Initialize(nodeID, metricsServer, logLevel string) {
	m.NodeID = nodeID
	m.MetricsServer = metricsServer
	m.LogLevel = logLevel
	m.data = make(map[string]interface{})
	go m.collectMetrics()
}

func (m *Metrics) collectMetrics() {
	for {
		m.mu.Lock()
		m.data["timestamp"] = time.Now().Unix()
		m.data["cpu_usage"] = common.GetCPUUsage()
		m.data["memory_usage"] = common.GetMemoryUsage()
		m.data["disk_usage"] = common.GetDiskUsage()
		m.data["network_latency"] = common.GetNetworkLatency()
		m.data["transactions_validated"] = common.GetTransactionsValidated()
		m.data["blocks_created"] = common.GetBlocksCreated()
		m.mu.Unlock()

		if err := m.sendMetrics(); err != nil {
			log.Printf("Error sending metrics: %v", err)
		}

		time.Sleep(10 * time.Second)
	}
}

func (m *Metrics) sendMetrics() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	metricsData, err := json.Marshal(m.data)
	if err != nil {
		return err
	}

	resp, err := http.Post(m.MetricsServer, "application/json", bytes.NewBuffer(metricsData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send metrics, status code: %d", resp.StatusCode)
	}

	return nil
}

func (m *Metrics) Log(level, message string) {
	if m.LogLevel == "debug" || (m.LogLevel == "info" && level != "debug") {
		log.Printf("[%s] %s", level, message)
	}
}

func (m *Metrics) GetCurrentMetrics() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data
}

func main() {
	metrics := &Metrics{}
	metrics.Initialize("unique-node-id", "http://localhost:9090", "info")
}
