package metrics

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"math"
	"gonum.org/v1/gonum/stat"
	"github.com/sasha-s/go-deadlock"
)

// AnomalyDetector is responsible for detecting anomalies in the collected metrics.
type AnomalyDetector struct {
	metricData      map[string][]float64
	alertChannel    chan Alert
	mu              deadlock.RWMutex
	detectionWindow int
}

// NewAnomalyDetector creates a new AnomalyDetector with a specified detection window.
func NewAnomalyDetector(window int) *AnomalyDetector {
	return &AnomalyDetector{
		metricData:      make(map[string][]float64),
		alertChannel:    make(chan Alert, 100),
		detectionWindow: window,
	}
}

// AddMetricData adds a new data point for a given metric.
func (ad *AnomalyDetector) AddMetricData(metricName string, value float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if _, exists := ad.metricData[metricName]; !exists {
		ad.metricData[metricName] = []float64{}
	}

	ad.metricData[metricName] = append(ad.metricData[metricName], value)
	if len(ad.metricData[metricName]) > ad.detectionWindow {
		ad.metricData[metricName] = ad.metricData[metricName][1:]
	}

	if len(ad.metricData[metricName]) == ad.detectionWindow {
		ad.detectAnomaly(metricName)
	}
}

// detectAnomaly detects anomalies in the metric data using statistical methods.
func (ad *AnomalyDetector) detectAnomaly(metricName string) {
	data := ad.metricData[metricName]
	mean, stddev := stat.MeanStdDev(data, nil)
	currentValue := data[len(data)-1]

	threshold := 3.0 // Number of standard deviations from the mean to consider as anomaly
	if math.Abs(currentValue-mean) > threshold*stddev {
		alert := Alert{
			MetricName:   metricName,
			CurrentValue: currentValue,
			AlertMessage: fmt.Sprintf("Anomaly detected in %s: value %f is beyond %f standard deviations from the mean", metricName, currentValue, threshold),
			Timestamp:    time.Now(),
		}
		ad.alertChannel <- alert
	}
}

// GetAlertChannel returns the alert channel for listening to triggered alerts.
func (ad *AnomalyDetector) GetAlertChannel() <-chan Alert {
	return ad.alertChannel
}

// MonitorMetrics sets up a Prometheus HTTP handler for exposing metrics and starts monitoring.
func (ad *AnomalyDetector) MonitorMetrics(port int) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			fmt.Printf("Error starting HTTP server: %v\n", err)
		}
	}()
}

// Example of setting up and using the AnomalyDetector.
func main() {
	anomalyDetector := NewAnomalyDetector(10)

	cpuUsage := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_usage",
		Help: "Current CPU usage",
	})

	prometheus.MustRegister(cpuUsage)

	anomalyDetector.MonitorMetrics(9090)

	go func() {
		for alert := range anomalyDetector.GetAlertChannel() {
			fmt.Printf("ALERT: %s - %f at %s\n", alert.AlertMessage, alert.CurrentValue, alert.Timestamp)
		}
	}()

	// Simulate metrics update
	for {
		value := float64(time.Now().UnixNano() % 100)
		cpuUsage.Set(value)
		anomalyDetector.AddMetricData("cpu_usage", value)
		time.Sleep(5 * time.Second)
	}
}
