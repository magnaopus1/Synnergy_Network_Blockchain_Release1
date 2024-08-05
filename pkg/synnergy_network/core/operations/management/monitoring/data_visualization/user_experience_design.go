package data_visualization

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
)

// DataPoint represents a single data point in the real-time data stream.
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// RealTimeDataStore manages the real-time data points.
type RealTimeDataStore struct {
	sync.Mutex
	dataPoints []DataPoint
}

// NewRealTimeDataStore creates a new instance of RealTimeDataStore.
func NewRealTimeDataStore() *RealTimeDataStore {
	return &RealTimeDataStore{
		dataPoints: make([]DataPoint, 0),
	}
}

// AddDataPoint adds a new data point to the store.
func (store *RealTimeDataStore) AddDataPoint(value float64) {
	store.Lock()
	defer store.Unlock()
	store.dataPoints = append(store.dataPoints, DataPoint{
		Timestamp: time.Now(),
		Value:     value,
	})
	if len(store.dataPoints) > 1000 { // Keep the last 1000 data points
		store.dataPoints = store.dataPoints[1:]
	}
}

// GetDataPoints returns all data points from the store.
func (store *RealTimeDataStore) GetDataPoints() []DataPoint {
	store.Lock()
	defer store.Unlock()
	return store.dataPoints
}

// RealTimeUpdater fetches data points from a real-time data source.
type RealTimeUpdater struct {
	store     *RealTimeDataStore
	fetchFunc func() (float64, error)
	ticker    *time.Ticker
	stopChan  chan struct{}
}

// NewRealTimeUpdater creates a new instance of RealTimeUpdater.
func NewRealTimeUpdater(store *RealTimeDataStore, fetchFunc func() (float64, error), interval time.Duration) *RealTimeUpdater {
	return &RealTimeUpdater{
		store:     store,
		fetchFunc: fetchFunc,
		ticker:    time.NewTicker(interval),
		stopChan:  make(chan struct{}),
	}
}

// Start begins the real-time data fetching.
func (updater *RealTimeUpdater) Start() {
	go func() {
		for {
			select {
			case <-updater.ticker.C:
				value, err := updater.fetchFunc()
				if err != nil {
					log.Printf("Error fetching data: %v", err)
					continue
				}
				updater.store.AddDataPoint(value)
			case <-updater.stopChan:
				return
			}
		}
	}()
}

// Stop stops the real-time data fetching.
func (updater *RealTimeUpdater) Stop() {
	updater.ticker.Stop()
	close(updater.stopChan)
}

// Prometheus metrics for real-time data updates.
var (
	realTimeDataMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "realtime_data",
			Help: "Real-time data values",
		},
		[]string{"source"},
	)
)

// InitMetrics initializes the Prometheus metrics.
func InitMetrics() {
	prometheus.MustRegister(realTimeDataMetric)
}

// FetchRealTimeData fetches real-time data and updates Prometheus metrics.
func FetchRealTimeData(source string, fetchFunc func() (float64, error)) {
	value, err := fetchFunc()
	if err != nil {
		log.Printf("Error fetching real-time data from %s: %v", source, err)
		return
	}
	realTimeDataMetric.WithLabelValues(source).Set(value)
}

// ServePrometheusMetrics starts the Prometheus HTTP handler.
func ServePrometheusMetrics(port int) {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// RealTimeDataAPI provides an HTTP API for real-time data.
type RealTimeDataAPI struct {
	store *RealTimeDataStore
}

// NewRealTimeDataAPI creates a new instance of RealTimeDataAPI.
func NewRealTimeDataAPI(store *RealTimeDataStore) *RealTimeDataAPI {
	return &RealTimeDataAPI{store: store}
}

// ServeHTTP serves real-time data via HTTP.
func (api *RealTimeDataAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dataPoints := api.store.GetDataPoints()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(dataPoints); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

