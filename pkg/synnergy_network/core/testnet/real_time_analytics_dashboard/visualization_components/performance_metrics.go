package visualizationcomponents

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// PerformanceMetric represents a single performance metric of the blockchain network
type PerformanceMetric struct {
	MetricID      string    `json:"metric_id"`
	Name          string    `json:"name"`
	Value         float64   `json:"value"`
	Unit          string    `json:"unit"`
	Timestamp     time.Time `json:"timestamp"`
}

// PerformanceMetricsManager manages the performance metrics of the blockchain network
type PerformanceMetricsManager struct {
	Metrics map[string]PerformanceMetric
	Mutex   sync.RWMutex
}

// InitializeManager initializes a new PerformanceMetricsManager
func (pmm *PerformanceMetricsManager) InitializeManager() {
	pmm.Metrics = make(map[string]PerformanceMetric)
}

// AddMetric adds a new performance metric to the manager
func (pmm *PerformanceMetricsManager) AddMetric(metric PerformanceMetric) {
	pmm.Mutex.Lock()
	defer pmm.Mutex.Unlock()
	pmm.Metrics[metric.MetricID] = metric
}

// UpdateMetric updates an existing performance metric in the manager
func (pmm *PerformanceMetricsManager) UpdateMetric(metric PerformanceMetric) error {
	pmm.Mutex.Lock()
	defer pmm.Mutex.Unlock()
	if _, exists := pmm.Metrics[metric.MetricID]; exists {
		pmm.Metrics[metric.MetricID] = metric
		return nil
	}
	return fmt.Errorf("metric with ID %s not found", metric.MetricID)
}

// RemoveMetric removes a performance metric from the manager
func (pmm *PerformanceMetricsManager) RemoveMetric(metricID string) error {
	pmm.Mutex.Lock()
	defer pmm.Mutex.Unlock()
	if _, exists := pmm.Metrics[metricID]; exists {
		delete(pmm.Metrics, metricID)
		return nil
	}
	return fmt.Errorf("metric with ID %s not found", metricID)
}

// GetMetric retrieves a specific performance metric by its ID
func (pmm *PerformanceMetricsManager) GetMetric(metricID string) (PerformanceMetric, error) {
	pmm.Mutex.RLock()
	defer pmm.Mutex.RUnlock()
	if metric, exists := pmm.Metrics[metricID]; exists {
		return metric, nil
	}
	return PerformanceMetric{}, fmt.Errorf("metric with ID %s not found", metricID)
}

// GetAllMetrics retrieves all performance metrics
func (pmm *PerformanceMetricsManager) GetAllMetrics() []PerformanceMetric {
	pmm.Mutex.RLock()
	defer pmm.Mutex.RUnlock()
	metrics := []PerformanceMetric{}
	for _, metric := range pmm.Metrics {
		metrics = append(metrics, metric)
	}
	return metrics
}

// ServeHTTP serves the performance metrics over HTTP
func (pmm *PerformanceMetricsManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		pmm.Mutex.RLock()
		defer pmm.Mutex.RUnlock()
		json.NewEncoder(w).Encode(pmm.GetAllMetrics())
	case http.MethodPost:
		var metric PerformanceMetric
		if err := json.NewDecoder(r.Body).Decode(&metric); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pmm.AddMetric(metric)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var metric PerformanceMetric
		if err := json.NewDecoder(r.Body).Decode(&metric); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := pmm.UpdateMetric(metric); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		var req struct {
			MetricID string `json:"metric_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := pmm.RemoveMetric(req.MetricID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Secure serves the performance metrics over HTTPS
func (pmm *PerformanceMetricsManager) Secure(certFile, keyFile string) error {
	srv := &http.Server{
		Addr:         ":443",
		Handler:      pmm,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// Example integration function for PerformanceMetricsManager
func integratePerformanceMetricsManager() {
	manager := &PerformanceMetricsManager{}
	manager.InitializeManager()

	http.Handle("/performance_metrics", manager)
	go func() {
		fmt.Println("Serving performance metrics on http://localhost:8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Println("Failed to start HTTP server:", err)
		}
	}()

	fmt.Println("Serving secure performance metrics on https://localhost")
	if err := manager.Secure("server.crt", "server.key"); err != nil {
		fmt.Println("Failed to start HTTPS server:", err)
	}
}
