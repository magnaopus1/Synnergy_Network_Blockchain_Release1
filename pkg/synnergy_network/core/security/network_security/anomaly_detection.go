package security

import (
	"log"
	"math"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Salt         = "your-unique-salt"
	KeyLength    = 32
	HistoryLimit = 1000 // Limit of historical data points to keep in memory
)

// DataPoint represents a single metric or event data point
type DataPoint struct {
	Timestamp time.Time
	Value     float64
}

// AnomalyDetector holds historical data and thresholds for anomaly detection
type AnomalyDetector struct {
	history   []DataPoint
	threshold float64
}

// NewAnomalyDetector initializes a new AnomalyDetector with a given threshold
func NewAnomalyDetector(threshold float64) *AnomalyDetector {
	return &AnomalyDetector{
		history:   make([]DataPoint, 0, HistoryLimit),
		threshold: threshold,
	}
}

// AddDataPoint adds a new data point to the history and checks for anomalies
func (ad *AnomalyDetector) AddDataPoint(dp DataPoint) {
	ad.history = append(ad.history, dp)
	if len(ad.history) > HistoryLimit {
		ad.history = ad.history[1:] // Maintain size of the history slice
	}
	ad.detectAnomalies(dp)
}

// detectAnomalies checks if the latest data point is an anomaly
func (ad *AnomalyDetector) detectAnomalies(dp DataPoint) {
	mean, stdDev := ad.calculateMeanAndStdDev()
	if math.Abs(dp.Value-mean) > ad.threshold*stdDev {
		log.Printf("Anomaly detected: Value %v at %v", dp.Value, dp.Timestamp)
	}
}

// calculateMeanAndStdDev calculates the mean and standard deviation of historical data
func (ad *AnomalyDetector) calculateMeanAndStdDev() (mean, stdDev float64) {
	sum := 0.0
	for _, dp := range ad.history {
		sum += dp.Value
	}
	mean = sum / float64(len(ad.history))

	variance := 0.0
	for _, dp := range ad.history {
		variance += (dp.Value - mean) * (dp.Value - mean)
	}
	stdDev = math.Sqrt(variance / float64(len(ad.history)))
	return mean, stdDev
}

// EncryptData uses Argon2 to encrypt sensitive data
func EncryptData(data []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
}

// DecryptData uses Scrypt to decrypt sensitive data
func DecryptData(data []byte) ([]byte, error) {
	dk, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

func main() {
	detector := NewAnomalyDetector(3) // Set threshold to 3 standard deviations
	// Simulated data stream
	for i := 0; i < 1000; i++ {
		dp := DataPoint{
			Timestamp: time.Now(),
			Value:     float64(i) + math.Sin(float64(i))*100, // Normal data with some noise
		}
		detector.AddDataPoint(dp)
		time.Sleep(10 * time.Millisecond)
	}
}
