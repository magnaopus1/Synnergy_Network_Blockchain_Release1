package metrics

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/argon2"
)

// MetricCollector manages the collection and reporting of metrics.
type MetricCollector struct {
	collectors map[string]prometheus.Collector
	mutex      sync.RWMutex
}

// NewMetricCollector creates a new MetricCollector.
func NewMetricCollector() *MetricCollector {
	return &MetricCollector{
		collectors: make(map[string]prometheus.Collector),
	}
}

// RegisterCollector registers a new metric collector.
func (mc *MetricCollector) RegisterCollector(name string, collector prometheus.Collector) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if _, exists := mc.collectors[name]; exists {
		return fmt.Errorf("collector %s already registered", name)
	}

	mc.collectors[name] = collector
	prometheus.MustRegister(collector)
	return nil
}

// UnregisterCollector unregisters an existing metric collector.
func (mc *MetricCollector) UnregisterCollector(name string) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	collector, exists := mc.collectors[name]
	if !exists {
		return fmt.Errorf("collector %s not found", name)
	}

	prometheus.Unregister(collector)
	delete(mc.collectors, name)
	return nil
}

// CollectMetrics collects and reports the metrics.
func (mc *MetricCollector) CollectMetrics() {
	for name, collector := range mc.collectors {
		fmt.Printf("Collecting metrics for: %s\n", name)
		collector.Collect(make(chan prometheus.Metric))
	}
}

// CreateGauge creates a new Prometheus gauge metric.
func (mc *MetricCollector) CreateGauge(name string, help string) prometheus.Gauge {
	return promauto.NewGauge(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	})
}

// CreateCounter creates a new Prometheus counter metric.
func (mc *MetricCollector) CreateCounter(name string, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{
		Name: name,
		Help: help,
	})
}

// CreateHistogram creates a new Prometheus histogram metric.
func (mc *MetricCollector) CreateHistogram(name string, help string) prometheus.Histogram {
	return promauto.NewHistogram(prometheus.HistogramOpts{
		Name: name,
		Help: help,
	})
}

// CreateSummary creates a new Prometheus summary metric.
func (mc *MetricCollector) CreateSummary(name string, help string) prometheus.Summary {
	return promauto.NewSummary(prometheus.SummaryOpts{
		Name: name,
		Help: help,
	})
}

// EncryptMetricData encrypts the metric data using Argon2 and AES.
func (mc *MetricCollector) EncryptMetricData(data []byte, password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// DecryptMetricData decrypts the metric data using Argon2 and AES.
func (mc *MetricCollector) DecryptMetricData(data []byte, password []byte) ([]byte, error) {
	salt := data[:16]
	data = data[16:]

	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

func main() {
	metricCollector := NewMetricCollector()

	cpuUsage := metricCollector.CreateGauge("cpu_usage", "Current CPU usage")
	metricCollector.RegisterCollector("cpu_usage", cpuUsage)

	go func() {
		for {
			value := float64(time.Now().UnixNano() % 100)
			cpuUsage.Set(value)
			time.Sleep(5 * time.Second)
		}
	}()

	select {}
}
