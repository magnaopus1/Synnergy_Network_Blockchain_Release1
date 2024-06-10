package consensus_monitoring

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// ForkEvent defines the structure to hold details about a fork event
type ForkEvent struct {
	BlockHeight int
	Timestamp   time.Time
	Details     string
}

// ForkDetection defines the structure for fork detection
type ForkDetection struct {
	forkEvents []ForkEvent
	mutex      sync.Mutex
}

// NewForkDetection initializes and returns a new ForkDetection object
func NewForkDetection() *ForkDetection {
	return &ForkDetection{
		forkEvents: make([]ForkEvent, 0),
	}
}

// RecordForkEvent records a new fork event
func (fd *ForkDetection) RecordForkEvent(blockHeight int, details string) {
	fd.mutex.Lock()
	defer fd.mutex.Unlock()
	fd.forkEvents = append(fd.forkEvents, ForkEvent{
		BlockHeight: blockHeight,
		Timestamp:   time.Now(),
		Details:     details,
	})
	log.Printf("Fork detected at block height %d: %s\n", blockHeight, details)
}

// GetForkEvents retrieves all recorded fork events
func (fd *ForkDetection) GetForkEvents() []ForkEvent {
	fd.mutex.Lock()
	defer fd.mutex.Unlock()
	return fd.forkEvents
}

// DetectFork checks if there is a fork in the blockchain at the given block height
func (fd *ForkDetection) DetectFork(blockHeight int, blockHashes []string) error {
	if len(blockHashes) < 2 {
		return errors.New("insufficient block hashes provided to detect a fork")
	}

	fd.mutex.Lock()
	defer fd.mutex.Unlock()

	uniqueHashes := make(map[string]bool)
	for _, hash := range blockHashes {
		uniqueHashes[hash] = true
	}

	if len(uniqueHashes) > 1 {
		forkDetails := fmt.Sprintf("Fork detected at block height %d with hashes: %v", blockHeight, blockHashes)
		fd.forkEvents = append(fd.forkEvents, ForkEvent{
			BlockHeight: blockHeight,
			Timestamp:   time.Now(),
			Details:     forkDetails,
		})
		log.Println(forkDetails)
		return errors.New(forkDetails)
	}

	return nil
}

// AnomalyDetection defines the structure for detecting anomalies in consensus metrics
type AnomalyDetection struct {
	thresholds AnomalyThresholds
}

// AnomalyThresholds defines the thresholds for detecting anomalies
type AnomalyThresholds struct {
	BlockValidationTimeThreshold float64
	ForkOccurrenceThreshold      int
	ChainReorganizationThreshold int
}

// NewAnomalyDetection initializes and returns a new AnomalyDetection object
func NewAnomalyDetection(thresholds AnomalyThresholds) *AnomalyDetection {
	return &AnomalyDetection{thresholds: thresholds}
}

// DetectAnomalies detects anomalies in the provided ConsensusMetrics
func (ad *AnomalyDetection) DetectAnomalies(metrics *ConsensusMetrics) {
	avgBlockValidationTime, err := metrics.GetAverageBlockValidationTime()
	if err != nil {
		log.Println("Error calculating average block validation time:", err)
		return
	}

	if avgBlockValidationTime > ad.thresholds.BlockValidationTimeThreshold {
		log.Printf("Anomaly detected: Average block validation time %.2f exceeds threshold %.2f\n", avgBlockValidationTime, ad.thresholds.BlockValidationTimeThreshold)
	}

	if metrics.ForkOccurrences > ad.thresholds.ForkOccurrenceThreshold {
		log.Printf("Anomaly detected: Fork occurrences %d exceed threshold %d\n", metrics.ForkOccurrences, ad.thresholds.ForkOccurrenceThreshold)
	}

	if metrics.ChainReorganizations > ad.thresholds.ChainReorganizationThreshold {
		log.Printf("Anomaly detected: Chain reorganizations %d exceed threshold %d\n", metrics.ChainReorganizations, ad.thresholds.ChainReorganizationThreshold)
	}
}

// HistoricalTrendAnalysis defines the structure for analyzing historical trends in consensus metrics
type HistoricalTrendAnalysis struct {
	metrics []ConsensusMetrics
	mutex   sync.Mutex
}

// NewHistoricalTrendAnalysis initializes and returns a new HistoricalTrendAnalysis object
func NewHistoricalTrendAnalysis() *HistoricalTrendAnalysis {
	return &HistoricalTrendAnalysis{
		metrics: make([]ConsensusMetrics, 0),
	}
}

// AddMetrics adds a new set of ConsensusMetrics for trend analysis
func (hta *HistoricalTrendAnalysis) AddMetrics(metrics ConsensusMetrics) {
	hta.mutex.Lock()
	defer hta.mutex.Unlock()
	hta.metrics = append(hta.metrics, metrics)
}

// AnalyzeTrends analyzes historical trends in the consensus metrics
func (hta *HistoricalTrendAnalysis) AnalyzeTrends() {
	hta.mutex.Lock()
	defer hta.mutex.Unlock()

	// Implement trend analysis logic (e.g., moving averages, detecting shifts in metrics)
	// Placeholder for trend analysis logic
	log.Println("Analyzing trends in consensus metrics...")
}

// RealTimeAlerts defines the structure for real-time alerting based on consensus metrics
type RealTimeAlerts struct {
	thresholds AnomalyThresholds
	alertChan  chan string
}

// NewRealTimeAlerts initializes and returns a new RealTimeAlerts object
func NewRealTimeAlerts(thresholds AnomalyThresholds) *RealTimeAlerts {
	return &RealTimeAlerts{
		thresholds: thresholds,
		alertChan:  make(chan string),
	}
}

// StartMonitoring starts the real-time monitoring and alerting process
func (rta *RealTimeAlerts) StartMonitoring(metrics *ConsensusMetrics) {
	go func() {
		for {
			select {
			case <-time.After(1 * time.Minute): // Check every minute
				rta.checkMetrics(metrics)
			}
		}
	}()
}

// checkMetrics checks the metrics against thresholds and sends alerts if necessary
func (rta *RealTimeAlerts) checkMetrics(metrics *ConsensusMetrics) {
	avgBlockValidationTime, err := metrics.GetAverageBlockValidationTime()
	if err != nil {
		log.Println("Error calculating average block validation time:", err)
		return
	}

	if avgBlockValidationTime > rta.thresholds.BlockValidationTimeThreshold {
		alert := fmt.Sprintf("Real-time alert: Average block validation time %.2f exceeds threshold %.2f", avgBlockValidationTime, rta.thresholds.BlockValidationTimeThreshold)
		log.Println(alert)
		rta.alertChan <- alert
	}

	if metrics.ForkOccurrences > rta.thresholds.ForkOccurrenceThreshold {
		alert := fmt.Sprintf("Real-time alert: Fork occurrences %d exceed threshold %d", metrics.ForkOccurrences, rta.thresholds.ForkOccurrenceThreshold)
		log.Println(alert)
		rta.alertChan <- alert
	}

	if metrics.ChainReorganizations > rta.thresholds.ChainReorganizationThreshold {
		alert := fmt.Sprintf("Real-time alert: Chain reorganizations %d exceed threshold %d", metrics.ChainReorganizations, rta.thresholds.ChainReorganizationThreshold)
		log.Println(alert)
		rta.alertChan <- alert
	}
}

// GetAlertChannel returns the alert channel
func (rta *RealTimeAlerts) GetAlertChannel() <-chan string {
	return rta.alertChan
}
