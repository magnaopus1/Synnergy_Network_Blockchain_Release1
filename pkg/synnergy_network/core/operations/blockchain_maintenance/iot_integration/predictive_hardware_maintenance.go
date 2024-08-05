package iot_integration

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

// Device represents an IoT device in the network.
type Device struct {
	ID             string
	Location       string
	LastMaintenance time.Time
	Status         string
	Metrics        DeviceMetrics
}

// DeviceMetrics represents the metrics collected from an IoT device.
type DeviceMetrics struct {
	Temperature float64
	Humidity    float64
	Vibration   float64
}

// PredictiveMaintenance represents the predictive maintenance logic for IoT devices.
type PredictiveMaintenance struct {
	Devices        map[string]*Device
	MetricsChannel chan DeviceMetrics
}

// NewPredictiveMaintenance creates a new PredictiveMaintenance instance.
func NewPredictiveMaintenance() *PredictiveMaintenance {
	return &PredictiveMaintenance{
		Devices:        make(map[string]*Device),
		MetricsChannel: make(chan DeviceMetrics),
	}
}

// AddDevice adds a new device to the maintenance system.
func (pm *PredictiveMaintenance) AddDevice(device *Device) {
	pm.Devices[device.ID] = device
}

// UpdateMetrics updates the metrics for a device and processes predictive maintenance logic.
func (pm *PredictiveMaintenance) UpdateMetrics(deviceID string, metrics DeviceMetrics) {
	if device, exists := pm.Devices[deviceID]; exists {
		device.Metrics = metrics
		pm.processMaintenance(device)
	} else {
		log.Printf("Device with ID %s not found.", deviceID)
	}
}

// processMaintenance processes the predictive maintenance logic for a device.
func (pm *PredictiveMaintenance) processMaintenance(device *Device) {
	// Simulate predictive maintenance logic
	if device.Metrics.Temperature > 75.0 || device.Metrics.Vibration > 5.0 {
		device.Status = "Maintenance Required"
		log.Printf("Device %s requires maintenance. Metrics: %+v", device.ID, device.Metrics)
	} else {
		device.Status = "Normal"
	}
}

// MonitorDevices continuously monitors devices for predictive maintenance.
func (pm *PredictiveMaintenance) MonitorDevices() {
	for metrics := range pm.MetricsChannel {
		for _, device := range pm.Devices {
			pm.UpdateMetrics(device.ID, metrics)
		}
	}
}

// Prometheus metrics
var (
	temperatureGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "device_temperature",
			Help: "Temperature of the device",
		},
		[]string{"device_id"},
	)
	vibrationGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "device_vibration",
			Help: "Vibration of the device",
		},
		[]string{"device_id"},
	)
)

// InitPrometheus initializes Prometheus metrics.
func (pm *PredictiveMaintenance) InitPrometheus() {
	prometheus.MustRegister(temperatureGauge)
	prometheus.MustRegister(vibrationGauge)

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":2112", nil)
}

// RecordMetrics records device metrics in Prometheus.
func (pm *PredictiveMaintenance) RecordMetrics(deviceID string, metrics DeviceMetrics) {
	temperatureGauge.With(prometheus.Labels{"device_id": deviceID}).Set(metrics.Temperature)
	vibrationGauge.With(prometheus.Labels{"device_id": deviceID}).Set(metrics.Vibration)
}

// SimulateData generates simulated data for a device.
func (pm *PredictiveMaintenance) SimulateData(deviceID string) {
	for {
		metrics := DeviceMetrics{
			Temperature: float64(65 + time.Now().UnixNano()%10),
			Vibration:   float64(1 + time.Now().UnixNano()%5),
		}
		pm.MetricsChannel <- metrics
		pm.RecordMetrics(deviceID, metrics)
		time.Sleep(10 * time.Second)
	}
}

// AlertIntegration sends an alert if the device requires maintenance.
func (pm *PredictiveMaintenance) AlertIntegration(device *Device) {
	if device.Status == "Maintenance Required" {
		alert := map[string]string{
			"device_id": device.ID,
			"status":    device.Status,
			"message":   fmt.Sprintf("Device %s requires maintenance.", device.ID),
		}
		alertJSON, _ := json.Marshal(alert)
		log.Printf("ALERT: %s", alertJSON)
		// Here you would integrate with an external alerting system
	}
}

func main() {
	pm := NewPredictiveMaintenance()
	pm.InitPrometheus()

	device := &Device{
		ID:       "device123",
		Location: "Data Center 1",
	}
	pm.AddDevice(device)

	go pm.MonitorDevices()
	go pm.SimulateData(device.ID)

	select {} // Keep the program running
}
