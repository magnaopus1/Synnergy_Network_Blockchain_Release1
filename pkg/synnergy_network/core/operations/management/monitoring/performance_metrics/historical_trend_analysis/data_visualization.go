package performance_metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DataVisualizationService represents the service for handling data visualization.
type DataVisualizationService struct {
	Router         *mux.Router
	MetricsStorage MetricsStorage
}

// MetricsStorage represents the interface for metrics storage.
type MetricsStorage interface {
	GetHistoricalData(metricName string, startTime, endTime time.Time) ([]MetricDataPoint, error)
}

// MetricDataPoint represents a single data point of a metric.
type MetricDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// NewDataVisualizationService creates a new DataVisualizationService.
func NewDataVisualizationService(router *mux.Router, storage MetricsStorage) *DataVisualizationService {
	service := &DataVisualizationService{
		Router:         router,
		MetricsStorage: storage,
	}

	service.Router.HandleFunc("/metrics/historical", service.handleGetHistoricalData).Methods("GET")
	service.Router.Handle("/metrics", promhttp.Handler())

	return service
}

// handleGetHistoricalData handles the request for historical data.
func (s *DataVisualizationService) handleGetHistoricalData(w http.ResponseWriter, r *http.Request) {
	metricName := r.URL.Query().Get("metric")
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	if metricName == "" || start == "" || end == "" {
		http.Error(w, "Missing query parameters", http.StatusBadRequest)
		return
	}

	startTime, err := time.Parse(time.RFC3339, start)
	if err != nil {
		http.Error(w, "Invalid start time format", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse(time.RFC3339, end)
	if err != nil {
		http.Error(w, "Invalid end time format", http.StatusBadRequest)
		return
	}

	dataPoints, err := s.MetricsStorage.GetHistoricalData(metricName, startTime, endTime)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving data: %v", err), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(dataPoints)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error marshalling data: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// MetricCollector represents the Prometheus metric collector.
type MetricCollector struct {
	histogram *prometheus.HistogramVec
}

// NewMetricCollector creates a new MetricCollector.
func NewMetricCollector() *MetricCollector {
	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "synnergy_network_metric",
		Help:    "A histogram of various metrics in the Synnergy Network",
		Buckets: prometheus.LinearBuckets(0, 10, 5),
	}, []string{"metric"})

	prometheus.MustRegister(histogram)

	return &MetricCollector{
		histogram: histogram,
	}
}

// RecordMetric records a new metric value.
func (c *MetricCollector) RecordMetric(metricName string, value float64) {
	c.histogram.WithLabelValues(metricName).Observe(value)
}

// StartServer starts the HTTP server for the data visualization service.
func StartServer(address string, service *DataVisualizationService) {
	srv := &http.Server{
		Handler:      service.Router,
		Addr:         address,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func main() {
	router := mux.NewRouter()
	storage := NewInMemoryMetricsStorage() // Replace with actual storage implementation.
	service := NewDataVisualizationService(router, storage)
	StartServer(":8080", service)
}

// InMemoryMetricsStorage is a simple in-memory implementation of MetricsStorage.
type InMemoryMetricsStorage struct {
	data map[string][]MetricDataPoint
}

// NewInMemoryMetricsStorage creates a new InMemoryMetricsStorage.
func NewInMemoryMetricsStorage() *InMemoryMetricsStorage {
	return &InMemoryMetricsStorage{
		data: make(map[string][]MetricDataPoint),
	}
}

// GetHistoricalData retrieves historical data for a given metric.
func (s *InMemoryMetricsStorage) GetHistoricalData(metricName string, startTime, endTime time.Time) ([]MetricDataPoint, error) {
	dataPoints, ok := s.data[metricName]
	if !ok {
		return nil, fmt.Errorf("metric not found")
	}

	var filteredData []MetricDataPoint
	for _, dp := range dataPoints {
		if dp.Timestamp.After(startTime) && dp.Timestamp.Before(endTime) {
			filteredData = append(filteredData, dp)
		}
	}

	return filteredData, nil
}

// AddDataPoint adds a data point to the storage.
func (s *InMemoryMetricsStorage) AddDataPoint(metricName string, dataPoint MetricDataPoint) {
	s.data[metricName] = append(s.data[metricName], dataPoint)
}
