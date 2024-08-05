package monitoring

import (
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "golang.org/x/crypto/argon2"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "io"
)

// TelemetryData holds the structure of the telemetry data.
type TelemetryData struct {
    NodeID     string    `json:"node_id"`
    Timestamp  time.Time `json:"timestamp"`
    CPUUsage   float64   `json:"cpu_usage"`
    MemoryUsage float64  `json:"memory_usage"`
    DiskUsage  float64   `json:"disk_usage"`
    NetworkIn  float64   `json:"network_in"`
    NetworkOut float64   `json:"network_out"`
}

// TelemetryMetrics holds the Prometheus metrics.
type TelemetryMetrics struct {
    CPUUsage    prometheus.Gauge
    MemoryUsage prometheus.Gauge
    DiskUsage   prometheus.Gauge
    NetworkIn   prometheus.Gauge
    NetworkOut  prometheus.Gauge
}

// NewTelemetryMetrics creates a new set of telemetry metrics.
func NewTelemetryMetrics(nodeID string) *TelemetryMetrics {
    return &TelemetryMetrics{
        CPUUsage: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: fmt.Sprintf("node_cpu_usage_%s", nodeID),
            Help: "Current CPU usage",
        }),
        MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: fmt.Sprintf("node_memory_usage_%s", nodeID),
            Help: "Current memory usage",
        }),
        DiskUsage: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: fmt.Sprintf("node_disk_usage_%s", nodeID),
            Help: "Current disk usage",
        }),
        NetworkIn: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: fmt.Sprintf("node_network_in_%s", nodeID),
            Help: "Current network input",
        }),
        NetworkOut: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: fmt.Sprintf("node_network_out_%s", nodeID),
            Help: "Current network output",
        }),
    }
}

// Register registers the telemetry metrics with Prometheus.
func (tm *TelemetryMetrics) Register() {
    prometheus.MustRegister(tm.CPUUsage, tm.MemoryUsage, tm.DiskUsage, tm.NetworkIn, tm.NetworkOut)
}

// TelemetryServer holds the server configuration for telemetry data collection.
type TelemetryServer struct {
    MetricsMap map[string]*TelemetryMetrics
}

// NewTelemetryServer creates a new telemetry server.
func NewTelemetryServer() *TelemetryServer {
    return &TelemetryServer{
        MetricsMap: make(map[string]*TelemetryMetrics),
    }
}

// EncryptData encrypts the telemetry data using AES encryption.
func EncryptData(data []byte, passphrase string) (string, error) {
    block, err := aes.NewCipher([]byte(passphrase))
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    encryptedData := gcm.Seal(nonce, nonce, data, nil)
    return base64.URLEncoding.EncodeToString(encryptedData), nil
}

// DecryptData decrypts the telemetry data using AES encryption.
func DecryptData(encryptedData string, passphrase string) ([]byte, error) {
    data, err := base64.URLEncoding.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher([]byte(passphrase))
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// CollectTelemetryData collects and processes the telemetry data.
func (ts *TelemetryServer) CollectTelemetryData(w http.ResponseWriter, r *http.Request) {
    var telemetryData TelemetryData
    passphrase := "your-secure-passphrase"

    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    if err := json.NewDecoder(r.Body).Decode(&telemetryData); err != nil {
        http.Error(w, "Failed to decode telemetry data", http.StatusBadRequest)
        return
    }

    encryptedData, err := EncryptData([]byte(telemetryData), passphrase)
    if err != nil {
        http.Error(w, "Failed to encrypt telemetry data", http.StatusInternalServerError)
        return
    }

    telemetryDataBytes, err := DecryptData(encryptedData, passphrase)
    if err != nil {
        http.Error(w, "Failed to decrypt telemetry data", http.StatusInternalServerError)
        return
    }

    if err := json.Unmarshal(telemetryDataBytes, &telemetryData); err != nil {
        http.Error(w, "Failed to unmarshal telemetry data", http.StatusInternalServerError)
        return
    }

    if _, exists := ts.MetricsMap[telemetryData.NodeID]; !exists {
        metrics := NewTelemetryMetrics(telemetryData.NodeID)
        metrics.Register()
        ts.MetricsMap[telemetryData.NodeID] = metrics
    }

    metrics := ts.MetricsMap[telemetryData.NodeID]
    metrics.CPUUsage.Set(telemetryData.CPUUsage)
    metrics.MemoryUsage.Set(telemetryData.MemoryUsage)
    metrics.DiskUsage.Set(telemetryData.DiskUsage)
    metrics.NetworkIn.Set(telemetryData.NetworkIn)
    metrics.NetworkOut.Set(telemetryData.NetworkOut)

    w.WriteHeader(http.StatusOK)
}

// Start starts the telemetry server.
func (ts *TelemetryServer) Start() {
    http.Handle("/metrics", promhttp.Handler())
    http.HandleFunc("/collect", ts.CollectTelemetryData)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
    server := NewTelemetryServer()
    fmt.Println("Starting telemetry server on port 8080")
    server.Start()
}
