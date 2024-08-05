package monitoring

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metric represents a single performance metric
type Metric struct {
	Name      string    `json:"name"`
	Value     float64   `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}

// Dashboard represents the monitoring dashboard
type Dashboard struct {
	mu        sync.Mutex
	metrics   map[string]Metric
	alerts    []Alert
	prometheusMetrics map[string]prometheus.Gauge
}

// NewDashboard creates a new monitoring dashboard
func NewDashboard() *Dashboard {
	return &Dashboard{
		metrics:           make(map[string]Metric),
		alerts:            []Alert{},
		prometheusMetrics: make(map[string]prometheus.Gauge),
	}
}

// AddMetric adds a new metric to the dashboard
func (d *Dashboard) AddMetric(name string, value float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	metric := Metric{
		Name:      name,
		Value:     value,
		Timestamp: time.Now(),
	}

	d.metrics[name] = metric
	if gauge, exists := d.prometheusMetrics[name]; exists {
		gauge.Set(value)
	} else {
		gauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: name,
			Help: "Metric " + name,
		})
		prometheus.MustRegister(gauge)
		gauge.Set(value)
		d.prometheusMetrics[name] = gauge
	}
}

// GetMetric retrieves a specific metric by name
func (d *Dashboard) GetMetric(name string) (Metric, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	metric, exists := d.metrics[name]
	if !exists {
		return Metric{}, errors.New("metric not found")
	}

	return metric, nil
}

// ListMetrics returns a list of all metrics
func (d *Dashboard) ListMetrics() []Metric {
	d.mu.Lock()
	defer d.mu.Unlock()

	metricList := make([]Metric, 0, len(d.metrics))
	for _, metric := range d.metrics {
		metricList = append(metricList, metric)
	}
	return metricList
}

// AddAlert adds a new alert to the dashboard
func (d *Dashboard) AddAlert(alert Alert) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.alerts = append(d.alerts, alert)
}

// ListAlerts returns a list of all current alerts
func (d *Dashboard) ListAlerts() []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.alerts
}

// SerializeDashboard serializes the dashboard to JSON
func (d *Dashboard) SerializeDashboard() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// DeserializeDashboard deserializes the dashboard from JSON
func (d *Dashboard) DeserializeDashboard(data string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var dashboard Dashboard
	if err := json.Unmarshal([]byte(data), &dashboard); err != nil {
		return err
	}

	d.metrics = dashboard.metrics
	d.alerts = dashboard.alerts
	return nil
}

// Example usage of the monitoring dashboard
func exampleUsage() {
	dashboard := NewDashboard()

	// Add metrics to the dashboard
	dashboard.AddMetric("cpu_usage", 85.0)
	dashboard.AddMetric("memory_usage", 70.5)

	// Retrieve a specific metric
	cpuUsage, _ := dashboard.GetMetric("cpu_usage")
	fmt.Println("CPU Usage:", cpuUsage)

	// List all metrics
	metrics := dashboard.ListMetrics()
	fmt.Println("All Metrics:", metrics)

	// Add an alert to the dashboard
	alert := Alert{
		ID:        "alert_1",
		Timestamp: time.Now(),
		Severity:  "high",
		Message:   "CPU usage exceeds 90%",
	}
	dashboard.AddAlert(alert)

	// List all alerts
	alerts := dashboard.ListAlerts()
	fmt.Println("All Alerts:", alerts)

	// Serialize dashboard to JSON
	jsonData, _ := dashboard.SerializeDashboard()
	fmt.Println("Serialized Dashboard:", jsonData)

	// Deserialize dashboard from JSON
	_ = dashboard.DeserializeDashboard(jsonData)
}
