// Package management handles the real-time monitoring of resources in the Synnergy Network.
package management

import (
    "time"
    "sync"
    "log"
    "errors"
    "fmt"
    "encoding/json"
    "os"
    "net/smtp"
)

// MetricType defines the types of metrics monitored
type MetricType string

const (
    CPUUsage       MetricType = "CPU_USAGE"
    MemoryUsage    MetricType = "MEMORY_USAGE"
    BandwidthUsage MetricType = "BANDWIDTH_USAGE"
    TransactionVolume MetricType = "TRANSACTION_VOLUME"
)

// Metric represents a single data point in monitoring
type Metric struct {
    Timestamp time.Time  `json:"timestamp"`
    NodeID    string     `json:"node_id"`
    Type      MetricType `json:"type"`
    Value     float64    `json:"value"`
}

// Alert represents a system alert for a metric threshold breach
type Alert struct {
    MetricType MetricType
    NodeID     string
    Value      float64
    Threshold  float64
    Message    string
    Timestamp  time.Time
}

// MonitoringConfig holds the configuration for the monitoring system
type MonitoringConfig struct {
    AlertThresholds map[MetricType]float64
    SmtpServer      string
    SmtpPort        int
    EmailSender     string
    EmailPassword   string
    Recipients      []string
}

// MonitoringSystem handles real-time monitoring of metrics
type MonitoringSystem struct {
    metrics       []Metric
    alerts        []Alert
    config        MonitoringConfig
    dataMutex     sync.Mutex
    alertMutex    sync.Mutex
}

// NewMonitoringSystem initializes a new MonitoringSystem
func NewMonitoringSystem(config MonitoringConfig) *MonitoringSystem {
    return &MonitoringSystem{
        metrics:       []Metric{},
        alerts:        []Alert{},
        config:        config,
    }
}

// CollectMetric collects and stores a new metric data point
func (ms *MonitoringSystem) CollectMetric(nodeID string, metricType MetricType, value float64) {
    ms.dataMutex.Lock()
    defer ms.dataMutex.Unlock()

    metric := Metric{
        Timestamp: time.Now(),
        NodeID:    nodeID,
        Type:      metricType,
        Value:     value,
    }
    ms.metrics = append(ms.metrics, metric)

    log.Printf("Collected metric: %v", metric)

    if value > ms.config.AlertThresholds[metricType] {
        ms.generateAlert(metric)
    }
}

// generateAlert creates an alert if a metric exceeds the threshold
func (ms *MonitoringSystem) generateAlert(metric Metric) {
    ms.alertMutex.Lock()
    defer ms.alertMutex.Unlock()

    alert := Alert{
        MetricType: metric.Type,
        NodeID:     metric.NodeID,
        Value:      metric.Value,
        Threshold:  ms.config.AlertThresholds[metric.Type],
        Message:    fmt.Sprintf("%s metric on Node %s exceeded threshold with value %.2f", metric.Type, metric.NodeID, metric.Value),
        Timestamp:  metric.Timestamp,
    }

    ms.alerts = append(ms.alerts, alert)
    log.Printf("Generated alert: %s", alert.Message)

    // Send notification
    ms.sendNotification(alert)
}

// sendNotification sends an email notification for an alert
func (ms *MonitoringSystem) sendNotification(alert Alert) {
    subject := fmt.Sprintf("Alert: %s on Node: %s", alert.MetricType, alert.NodeID)
    body := fmt.Sprintf("Timestamp: %s\nNodeID: %s\nMetric: %s\nValue: %.2f\nThreshold: %.2f\nMessage: %s\n",
        alert.Timestamp.Format(time.RFC3339), alert.NodeID, alert.MetricType, alert.Value, alert.Threshold, alert.Message)

    message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s",
        ms.config.EmailSender, ms.config.Recipients, subject, body)

    err := smtp.SendMail(
        fmt.Sprintf("%s:%d", ms.config.SmtpServer, ms.config.SmtpPort),
        smtp.PlainAuth("", ms.config.EmailSender, ms.config.EmailPassword, ms.config.SmtpServer),
        ms.config.EmailSender,
        ms.config.Recipients,
        []byte(message),
    )

    if err != nil {
        log.Printf("Error sending email notification: %v", err)
    } else {
        log.Printf("Notification sent for alert: %s", alert.Message)
    }
}

// SaveMetricsToFile saves the collected metrics to a JSON file
func (ms *MonitoringSystem) SaveMetricsToFile(filename string) error {
    ms.dataMutex.Lock()
    defer ms.dataMutex.Unlock()

    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    return encoder.Encode(ms.metrics)
}

// LoadMetricsFromFile loads metrics from a JSON file
func (ms *MonitoringSystem) LoadMetricsFromFile(filename string) error {
    ms.dataMutex.Lock()
    defer ms.dataMutex.Unlock()

    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    return decoder.Decode(&ms.metrics)
}

// SaveAlertsToFile saves the generated alerts to a JSON file
func (ms *MonitoringSystem) SaveAlertsToFile(filename string) error {
    ms.alertMutex.Lock()
    defer ms.alertMutex.Unlock()

    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    return encoder.Encode(ms.alerts)
}

// LoadAlertsFromFile loads alerts from a JSON file
func (ms *MonitoringSystem) LoadAlertsFromFile(filename string) error {
    ms.alertMutex.Lock()
    defer ms.alertMutex.Unlock()

    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    return decoder.Decode(&ms.alerts)
}
