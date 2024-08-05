package historical_data_analysis

import (
    "fmt"
    "log"
    "time"
    "context"
    "github.com/segmentio/kafka-go"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

// IngestedData represents the structure of the data to be ingested
type IngestedData struct {
    Timestamp   time.Time
    NodeID      string
    MetricType  string
    MetricValue float64
}

// DataIngestionService handles the streaming data ingestion
type DataIngestionService struct {
    KafkaReader *kafka.Reader
    Metrics     *prometheus.HistogramVec
}

// NewDataIngestionService initializes a new DataIngestionService
func NewDataIngestionService(brokers []string, topic string, groupID string) *DataIngestionService {
    r := kafka.NewReader(kafka.ReaderConfig{
        Brokers: brokers,
        Topic:   topic,
        GroupID: groupID,
    })

    metrics := prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "ingested_data_metrics",
        Help:    "Metrics for ingested data",
        Buckets: prometheus.LinearBuckets(0, 5, 20),
    }, []string{"node_id", "metric_type"})

    prometheus.MustRegister(metrics)

    return &DataIngestionService{
        KafkaReader: r,
        Metrics:     metrics,
    }
}

// Start begins the data ingestion process
func (s *DataIngestionService) Start(ctx context.Context) {
    for {
        m, err := s.KafkaReader.FetchMessage(ctx)
        if err != nil {
            log.Printf("could not fetch message: %v", err)
            continue
        }

        data, err := s.processMessage(m)
        if err != nil {
            log.Printf("could not process message: %v", err)
            continue
        }

        s.recordMetrics(data)

        if err := s.KafkaReader.CommitMessages(ctx, m); err != nil {
            log.Printf("could not commit message: %v", err)
        }
    }
}

// processMessage processes a single Kafka message
func (s *DataIngestionService) processMessage(m kafka.Message) (*IngestedData, error) {
    var data IngestedData
    err := json.Unmarshal(m.Value, &data)
    if err != nil {
        return nil, fmt.Errorf("could not unmarshal message: %w", err)
    }
    return &data, nil
}

// recordMetrics records the metrics using Prometheus
func (s *DataIngestionService) recordMetrics(data *IngestedData) {
    s.Metrics.With(prometheus.Labels{"node_id": data.NodeID, "metric_type": data.MetricType}).Observe(data.MetricValue)
}

// ServeMetrics serves the Prometheus metrics endpoint
func (s *DataIngestionService) ServeMetrics(addr string) {
    http.Handle("/metrics", promhttp.Handler())
    log.Fatal(http.ListenAndServe(addr, nil))
}

// Close closes the Kafka reader
func (s *DataIngestionService) Close() {
    if err := s.KafkaReader.Close(); err != nil {
        log.Printf("could not close kafka reader: %v", err)
    }
}

func main() {
    ctx := context.Background()
    brokers := []string{"localhost:9092"}
    topic := "blockchain-metrics"
    groupID := "metrics-ingestion-group"

    service := NewDataIngestionService(brokers, topic, groupID)

    go service.Start(ctx)
    service.ServeMetrics(":2112")
}
