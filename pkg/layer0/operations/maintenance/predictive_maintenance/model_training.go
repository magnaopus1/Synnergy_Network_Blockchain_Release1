package predictive_maintenance

import (
	"encoding/csv"
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gonum/stat"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/optimize"
)

// Node represents a blockchain node with operational data
type Node struct {
	ID             string
	IPAddress      string
	Role           string
	LastHeartbeat  time.Time
	IsHealthy      bool
	PublicKey      string
	PerformanceData []PerformanceMetric
}

// PerformanceMetric represents a single performance data point for a node
type PerformanceMetric struct {
	Timestamp   time.Time
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
}

// DataAnalysis provides methods for predictive maintenance using data analysis
type DataAnalysis struct {
	Nodes []Node
}

// NewDataAnalysis initializes a new DataAnalysis instance
func NewDataAnalysis(nodes []Node) *DataAnalysis {
	return &DataAnalysis{
		Nodes: nodes,
	}
}

// CollectData collects operational data from nodes and saves it to a CSV file
func (da *DataAnalysis) CollectData(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"NodeID", "Timestamp", "CPUUsage", "MemoryUsage", "DiskUsage"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, node := range da.Nodes {
		for _, metric := range node.PerformanceData {
			record := []string{
				node.ID,
				metric.Timestamp.Format(time.RFC3339),
				strconv.FormatFloat(metric.CPUUsage, 'f', 2, 64),
				strconv.FormatFloat(metric.MemoryUsage, 'f', 2, 64),
				strconv.FormatFloat(metric.DiskUsage, 'f', 2, 64),
			}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadData loads operational data from a CSV file into the nodes
func (da *DataAnalysis) LoadData(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if i == 0 {
			continue
		}
		nodeID := record[0]
		timestamp, _ := time.Parse(time.RFC3339, record[1])
		cpuUsage, _ := strconv.ParseFloat(record[2], 64)
		memoryUsage, _ := strconv.ParseFloat(record[3], 64)
		diskUsage, _ := strconv.ParseFloat(record[4], 64)

		metric := PerformanceMetric{
			Timestamp:   timestamp,
			CPUUsage:    cpuUsage,
			MemoryUsage: memoryUsage,
			DiskUsage:   diskUsage,
		}

		for j := range da.Nodes {
			if da.Nodes[j].ID == nodeID {
				da.Nodes[j].PerformanceData = append(da.Nodes[j].PerformanceData, metric)
			}
		}
	}
	return nil
}

// TrainModel trains a predictive maintenance model using historical data
func (da *DataAnalysis) TrainModel() (*optimize.Result, error) {
	var allMetrics []float64

	for _, node := range da.Nodes {
		for _, metric := range node.PerformanceData {
			allMetrics = append(allMetrics, metric.CPUUsage, metric.MemoryUsage, metric.DiskUsage)
		}
	}

	if len(allMetrics) == 0 {
		return nil, errors.New("no data available for training")
	}

	mean := stat.Mean(allMetrics, nil)
	stddev := stat.StdDev(allMetrics, nil)

	model := &MaintenanceModel{
		Mean:   mean,
		StdDev: stddev,
	}

	initialGuess := []float64{model.Mean, model.StdDev}
	problem := optimize.Problem{
		Func: model.Evaluate,
	}

	result, err := optimize.Minimize(problem, initialGuess, nil, nil)
	if err != nil {
		return nil, err
	}

	model.Mean = result.X[0]
	model.StdDev = result.X[1]

	return result, nil
}

// MaintenanceModel represents a predictive maintenance model
type MaintenanceModel struct {
	Mean   float64
	StdDev float64
}

// Evaluate evaluates the maintenance model
func (m *MaintenanceModel) Evaluate(x []float64) float64 {
	mean := x[0]
	stddev := x[1]

	return (mean - m.Mean) * (mean - m.Mean) / (2 * stddev * stddev)
}

// PredictFailure predicts potential node failures based on the trained model
func (da *DataAnalysis) PredictFailure(model *MaintenanceModel) {
	for _, node := range da.Nodes {
		for _, metric := range node.PerformanceData {
			zScore := (metric.CPUUsage - model.Mean) / model.StdDev
			if zScore > 2.0 {
				log.Printf("Node %s predicted to fail based on high CPU usage at %s", node.ID, metric.Timestamp)
			}
		}
	}
}

// Argon2Mining performs mining using Argon2 for proof of work
func Argon2Mining(input string) string {
	salt := []byte("somesalt")
	hash := argon2.IDKey([]byte(input), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

// ScryptMining performs mining using Scrypt for proof of work
func ScryptMining(input string) (string, error) {
	salt := []byte("somesalt")
	hash, err := scrypt.Key([]byte(input), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hash), nil
}

func main() {
	// Example usage of the DataAnalysis system
	nodes := []Node{
		{ID: "node1", IPAddress: "192.168.1.1", Role: "validator", PublicKey: "publicKey1"},
		{ID: "node2", IPAddress: "192.168.1.2", Role: "super", PublicKey: "publicKey2"},
	}

	dataAnalysis := NewDataAnalysis(nodes)

	// Collect data from nodes
	filePath := "performance_data.csv"
	if err := dataAnalysis.CollectData(filePath); err != nil {
		log.Fatalf("Failed to collect data: %v", err)
	}

	// Load data into nodes
	if err := dataAnalysis.LoadData(filePath); err != nil {
		log.Fatalf("Failed to load data: %v", err)
	}

	// Train the model
	result, err := dataAnalysis.TrainModel()
	if err != nil {
		log.Fatalf("Failed to train model: %v", err)
	}
	log.Printf("Model trained with result: %+v", result)

	// Predict potential failures
	dataAnalysis.PredictFailure(&MaintenanceModel{
		Mean:   result.X[0],
		StdDev: result.X[1],
	})

	// Mining examples
	argon2Hash := Argon2Mining("example data")
	log.Printf("Argon2 hash: %s", argon2Hash)

	scryptHash, err := ScryptMining("example data")
	if err != nil {
		log.Fatalf("Failed to generate Scrypt hash: %v", err)
	}
	log.Printf("Scrypt hash: %s", scryptHash)
}
