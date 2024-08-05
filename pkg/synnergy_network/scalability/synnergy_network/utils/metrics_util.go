package metrics_util

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all the metrics to be collected
type Metrics struct {
	RequestsTotal        *prometheus.CounterVec
	RequestDuration      *prometheus.HistogramVec
	ErrorsTotal          *prometheus.CounterVec
	BlockProcessingTime  *prometheus.HistogramVec
	TransactionProcessingTime *prometheus.HistogramVec
	NodeHealth           *prometheus.GaugeVec
	mutex                sync.Mutex
}

// NewMetrics creates a new Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "requests_total",
				Help: "Total number of requests",
			},
			[]string{"endpoint", "method"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "request_duration_seconds",
				Help:    "Duration of requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"endpoint", "method"},
		),
		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "errors_total",
				Help: "Total number of errors",
			},
			[]string{"endpoint", "method"},
		),
		BlockProcessingTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "block_processing_time_seconds",
				Help:    "Time taken to process a block",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"node"},
		),
		TransactionProcessingTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "transaction_processing_time_seconds",
				Help:    "Time taken to process a transaction",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"node"},
		),
		NodeHealth: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "node_health_status",
				Help: "Health status of nodes",
			},
			[]string{"node"},
		),
	}
}

// RegisterMetrics registers all metrics with Prometheus
func (m *Metrics) RegisterMetrics() {
	prometheus.MustRegister(m.RequestsTotal)
	prometheus.MustRegister(m.RequestDuration)
	prometheus.MustRegister(m.ErrorsTotal)
	prometheus.MustRegister(m.BlockProcessingTime)
	prometheus.MustRegister(m.TransactionProcessingTime)
	prometheus.MustRegister(m.NodeHealth)
}

// IncrementRequests increments the request counter
func (m *Metrics) IncrementRequests(endpoint, method string) {
	m.RequestsTotal.WithLabelValues(endpoint, method).Inc()
}

// ObserveRequestDuration observes the duration of a request
func (m *Metrics) ObserveRequestDuration(endpoint, method string, duration time.Duration) {
	m.RequestDuration.WithLabelValues(endpoint, method).Observe(duration.Seconds())
}

// IncrementErrors increments the error counter
func (m *Metrics) IncrementErrors(endpoint, method string) {
	m.ErrorsTotal.WithLabelValues(endpoint, method).Inc()
}

// ObserveBlockProcessingTime observes the time taken to process a block
func (m *Metrics) ObserveBlockProcessingTime(node string, duration time.Duration) {
	m.BlockProcessingTime.WithLabelValues(node).Observe(duration.Seconds())
}

// ObserveTransactionProcessingTime observes the time taken to process a transaction
func (m *Metrics) ObserveTransactionProcessingTime(node string, duration time.Duration) {
	m.TransactionProcessingTime.WithLabelValues(node).Observe(duration.Seconds())
}

// SetNodeHealth sets the health status of a node
func (m *Metrics) SetNodeHealth(node string, status float64) {
	m.NodeHealth.WithLabelValues(node).Set(status)
}

// StartMetricsServer starts the metrics server
func StartMetricsServer(address string) {
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Starting metrics server at %s\n", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Failed to start metrics server: %v", err)
	}
}

// Example usage of how to observe metrics in the real world
func ExampleUsage() {
	metrics := NewMetrics()
	metrics.RegisterMetrics()

	go StartMetricsServer(":2112")

	// Simulating request processing
	endpoint := "/api/v1/resource"
	method := "GET"
	start := time.Now()

	// Simulate processing time
	time.Sleep(2 * time.Second)

	duration := time.Since(start)
	metrics.IncrementRequests(endpoint, method)
	metrics.ObserveRequestDuration(endpoint, method, duration)

	// Simulating block processing
	node := "node-1"
	blockProcessingStart := time.Now()

	// Simulate block processing time
	time.Sleep(5 * time.Second)

	blockProcessingDuration := time.Since(blockProcessingStart)
	metrics.ObserveBlockProcessingTime(node, blockProcessingDuration)

	// Simulating transaction processing
	transactionProcessingStart := time.Now()

	// Simulate transaction processing time
	time.Sleep(1 * time.Second)

	transactionProcessingDuration := time.Since(transactionProcessingStart)
	metrics.ObserveTransactionProcessingTime(node, transactionProcessingDuration)

	// Simulating node health status
	nodeHealthStatus := 1.0 // Assume 1.0 means healthy, 0.0 means unhealthy
	metrics.SetNodeHealth(node, nodeHealthStatus)

	// Simulating an error
	metrics.IncrementErrors(endpoint, method)
}
