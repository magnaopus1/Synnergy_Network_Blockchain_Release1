package consensus_monitoring

import (
	"errors"
	"log"
	"sync"
	"time"
)

// ConsensusMetrics defines the structure to hold consensus metrics data
type ConsensusMetrics struct {
	BlockValidationTimes []float64 // Time taken to validate blocks
	ForkOccurrences      int       // Number of fork occurrences
	ChainReorganizations int       // Number of chain reorganizations
	mutex                sync.Mutex
}

// NewConsensusMetrics initializes and returns a new ConsensusMetrics object
func NewConsensusMetrics() *ConsensusMetrics {
	return &ConsensusMetrics{
		BlockValidationTimes: make([]float64, 0),
		ForkOccurrences:      0,
		ChainReorganizations: 0,
	}
}

// RecordBlockValidationTime records the time taken to validate a block
func (cm *ConsensusMetrics) RecordBlockValidationTime(duration float64) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.BlockValidationTimes = append(cm.BlockValidationTimes, duration)
}

// RecordForkOccurrence increments the count of fork occurrences
func (cm *ConsensusMetrics) RecordForkOccurrence() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.ForkOccurrences++
}

// RecordChainReorganization increments the count of chain reorganizations
func (cm *ConsensusMetrics) RecordChainReorganization() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.ChainReorganizations++
}

// GetAverageBlockValidationTime calculates the average block validation time
func (cm *ConsensusMetrics) GetAverageBlockValidationTime() (float64, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if len(cm.BlockValidationTimes) == 0 {
		return 0, errors.New("no block validation times recorded")
	}

	total := 0.0
	for _, time := range cm.BlockValidationTimes {
		total += time
	}
	return total / float64(len(cm.BlockValidationTimes)), nil
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
