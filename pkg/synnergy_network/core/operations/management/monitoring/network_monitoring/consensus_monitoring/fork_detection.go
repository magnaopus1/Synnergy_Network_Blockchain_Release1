package consensus_monitoring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/argon2"
)

// ForkDetectionMetrics holds the Prometheus metrics for fork detection
type ForkDetectionMetrics struct {
	ForkCount        prometheus.Counter
	LastForkTime     prometheus.Gauge
	ForkResolutionTime prometheus.Histogram
	ForkSeverity     prometheus.Gauge
}

// NewForkDetectionMetrics initializes and returns a new ForkDetectionMetrics instance
func NewForkDetectionMetrics() *ForkDetectionMetrics {
	return &ForkDetectionMetrics{
		ForkCount: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fork_count",
			Help: "Total number of forks detected",
		}),
		LastForkTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "last_fork_time_seconds",
			Help: "Timestamp of the last detected fork",
		}),
		ForkResolutionTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "fork_resolution_time_seconds",
			Help:    "Time taken to resolve a fork",
			Buckets: prometheus.DefBuckets,
		}),
		ForkSeverity: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fork_severity",
			Help: "Severity of the last detected fork",
		}),
	}
}

// Register registers the metrics with Prometheus
func (fdm *ForkDetectionMetrics) Register() {
	prometheus.MustRegister(fdm.ForkCount)
	prometheus.MustRegister(fdm.LastForkTime)
	prometheus.MustRegister(fdm.ForkResolutionTime)
	prometheus.MustRegister(fdm.ForkSeverity)
}

// ForkDetection represents the main structure for fork detection logic
type ForkDetection struct {
	metrics      *ForkDetectionMetrics
	detectedForks []ForkEvent
	mu           sync.Mutex
}

// ForkEvent represents a detected fork event
type ForkEvent struct {
	Timestamp time.Time
	Severity  float64
	Details   string
}

// NewForkDetection initializes and returns a new ForkDetection instance
func NewForkDetection() *ForkDetection {
	return &ForkDetection{
		metrics: NewForkDetectionMetrics(),
	}
}

// DetectFork simulates fork detection and logs the event
func (fd *ForkDetection) DetectFork(severity float64, details string) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	now := time.Now()
	fd.metrics.ForkCount.Inc()
	fd.metrics.LastForkTime.Set(float64(now.Unix()))
	fd.metrics.ForkSeverity.Set(severity)
	fd.detectedForks = append(fd.detectedForks, ForkEvent{
		Timestamp: now,
		Severity:  severity,
		Details:   details,
	})
	log.Printf("Fork detected: %s", details)
}

// ResolveFork simulates fork resolution and updates the metrics
func (fd *ForkDetection) ResolveFork(startTime time.Time) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	now := time.Now()
	duration := now.Sub(startTime).Seconds()
	fd.metrics.ForkResolutionTime.Observe(duration)
	log.Printf("Fork resolved in %f seconds", duration)
}

// HashForkEvent hashes a fork event using Argon2
func HashForkEvent(event ForkEvent, salt []byte) (string, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey(data, salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// LogForkEvent logs the fork event using logrus
func LogForkEvent(event ForkEvent) {
	log.Printf("ForkEvent - Timestamp: %s, Severity: %f, Details: %s",
		event.Timestamp, event.Severity, event.Details)
}

// StartMetricsServer starts the HTTP server for serving Prometheus metrics
func StartMetricsServer(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(addr, nil))
}

// MonitorForks simulates fork monitoring in a loop
func (fd *ForkDetection) MonitorForks(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Simulate fork detection
			severity := float64(time.Now().UnixNano()%10 + 1)
			fd.DetectFork(severity, "Simulated fork detected for testing.")
		}
	}
}

func main() {
	// Initialize fork detection
	forkDetection := NewForkDetection()
	forkDetection.metrics.Register()

	// Start the metrics server
	go StartMetricsServer(":2113")

	// Start fork monitoring
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go forkDetection.MonitorForks(ctx, wg)

	// Wait for monitoring to complete
	wg.Wait()
	cancel()
}
