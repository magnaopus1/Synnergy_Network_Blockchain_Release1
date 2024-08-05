package decentralized_monitoring_network

import (
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/encryption"
	"github.com/synnergy_network/monitoring"
	"github.com/synnergy_network/utils"
)

// MonitoringParameters holds the dynamic parameters for monitoring
type MonitoringParameters struct {
	LatencyThreshold    int
	ThroughputThreshold int
	ErrorRateThreshold  float64
	mutex               sync.RWMutex
}

// AdaptiveMonitoringParameters manages the dynamic adjustment of monitoring parameters
type AdaptiveMonitoringParameters struct {
	Parameters        MonitoringParameters
	FeedbackChannel   chan monitoring.Metrics
	StopChannel       chan struct{}
	AdjustmentInterval time.Duration
}

// NewAdaptiveMonitoringParameters initializes AdaptiveMonitoringParameters with default values
func NewAdaptiveMonitoringParameters() *AdaptiveMonitoringParameters {
	return &AdaptiveMonitoringParameters{
		Parameters: MonitoringParameters{
			LatencyThreshold:    100,
			ThroughputThreshold: 1000,
			ErrorRateThreshold:  0.01,
		},
		FeedbackChannel:   make(chan monitoring.Metrics),
		StopChannel:       make(chan struct{}),
		AdjustmentInterval: 10 * time.Minute,
	}
}

// Start begins the dynamic adjustment process
func (amp *AdaptiveMonitoringParameters) Start() {
	go func() {
		for {
			select {
			case <-amp.StopChannel:
				return
			case metrics := <-amp.FeedbackChannel:
				amp.AdjustParameters(metrics)
			case <-time.After(amp.AdjustmentInterval):
				amp.EvaluateNetworkConditions()
			}
		}
	}()
}

// Stop halts the dynamic adjustment process
func (amp *AdaptiveMonitoringParameters) Stop() {
	close(amp.StopChannel)
}

// AdjustParameters dynamically adjusts the monitoring parameters based on real-time metrics
func (amp *AdaptiveMonitoringParameters) AdjustParameters(metrics monitoring.Metrics) {
	amp.Parameters.mutex.Lock()
	defer amp.Parameters.mutex.Unlock()

	if metrics.Latency > amp.Parameters.LatencyThreshold {
		amp.Parameters.LatencyThreshold += 10
	} else {
		amp.Parameters.LatencyThreshold -= 5
	}

	if metrics.Throughput < amp.Parameters.ThroughputThreshold {
		amp.Parameters.ThroughputThreshold -= 50
	} else {
		amp.Parameters.ThroughputThreshold += 25
	}

	if metrics.ErrorRate > amp.Parameters.ErrorRateThreshold {
		amp.Parameters.ErrorRateThreshold += 0.005
	} else {
		amp.Parameters.ErrorRateThreshold -= 0.002
	}

	log.Printf("Adjusted Parameters: LatencyThreshold=%d, ThroughputThreshold=%d, ErrorRateThreshold=%f",
		amp.Parameters.LatencyThreshold, amp.Parameters.ThroughputThreshold, amp.Parameters.ErrorRateThreshold)
}

// EvaluateNetworkConditions periodically assesses the network conditions to preemptively adjust parameters
func (amp *AdaptiveMonitoringParameters) EvaluateNetworkConditions() {
	metrics := monitoring.CollectMetrics()
	amp.AdjustParameters(metrics)
}

// EncryptParameters encrypts the monitoring parameters for secure transmission
func (amp *AdaptiveMonitoringParameters) EncryptParameters() ([]byte, error) {
	amp.Parameters.mutex.RLock()
	defer amp.Parameters.mutex.RUnlock()

	data, err := utils.Serialize(amp.Parameters)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encryption.Encrypt(data)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptParameters decrypts the monitoring parameters
func (amp *AdaptiveMonitoringParameters) DecryptParameters(data []byte) error {
	decryptedData, err := encryption.Decrypt(data)
	if err != nil {
		return err
	}

	var params MonitoringParameters
	if err := utils.Deserialize(decryptedData, &params); err != nil {
		return err
	}

	amp.Parameters.mutex.Lock()
	defer amp.Parameters.mutex.Unlock()

	amp.Parameters = params
	return nil
}
