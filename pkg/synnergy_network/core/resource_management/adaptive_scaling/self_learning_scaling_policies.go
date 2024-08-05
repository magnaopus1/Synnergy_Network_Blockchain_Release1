package adaptive_scaling

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/optimize"
)

// SelfLearningScalingPolicies handles adaptive scaling based on self-learning algorithms
type SelfLearningScalingPolicies struct {
	mu               sync.Mutex
	historicalData   []ScalingData
	models           []ScalingModel
	resourceThresholds ResourceThresholds
}

// ScalingData represents historical data used for training scaling models
type ScalingData struct {
	Timestamp        time.Time
	CPUUsage         float64
	MemoryUsage      float64
	NetworkUsage     float64
	TransactionRate  float64
	NodesCount       int
}

// ScalingModel represents a machine learning model used for predictive scaling
type ScalingModel struct {
	ModelID    string
	ModelType  string
	Parameters []float64
}

// ResourceThresholds defines thresholds for scaling actions
type ResourceThresholds struct {
	CPUUtilizationHigh  float64
	CPUUtilizationLow   float64
	MemoryUtilizationHigh float64
	MemoryUtilizationLow  float64
	NetworkUtilizationHigh float64
	NetworkUtilizationLow  float64
}

// NewSelfLearningScalingPolicies initializes a new instance
func NewSelfLearningScalingPolicies() *SelfLearningScalingPolicies {
	return &SelfLearningScalingPolicies{
		historicalData:   make([]ScalingData, 0),
		models:           make([]ScalingModel, 0),
		resourceThresholds: ResourceThresholds{},
	}
}

// AddScalingData adds historical data for model training
func (slsp *SelfLearningScalingPolicies) AddScalingData(data ScalingData) {
	slsp.mu.Lock()
	defer slsp.mu.Unlock()
	slsp.historicalData = append(slsp.historicalData, data)
}

// TrainModels trains machine learning models for predictive scaling
func (slsp *SelfLearningScalingPolicies) TrainModels() error {
	slsp.mu.Lock()
	defer slsp.mu.Unlock()

	if len(slsp.historicalData) == 0 {
		return errors.New("no historical data available for training models")
	}

	cpuUsage := extractData(slsp.historicalData, "CPU")
	memoryUsage := extractData(slsp.historicalData, "Memory")
	networkUsage := extractData(slsp.historicalData, "Network")
	transactionRate := extractData(slsp.historicalData, "Transaction")

	slsp.models = append(slsp.models, trainModel("CPU", cpuUsage, transactionRate))
	slsp.models = append(slsp.models, trainModel("Memory", memoryUsage, transactionRate))
	slsp.models = append(slsp.models, trainModel("Network", networkUsage, transactionRate))

	return nil
}

// PredictScalingAction predicts the necessary scaling actions based on current data
func (slsp *SelfLearningScalingPolicies) PredictScalingAction(currentData ScalingData) map[string]float64 {
	slsp.mu.Lock()
	defer slsp.mu.Unlock()

	predictions := make(map[string]float64)

	for _, model := range slsp.models {
		switch model.ModelID {
		case "CPU":
			predictions["CPU"] = predictUsage(currentData.TransactionRate, model)
		case "Memory":
			predictions["Memory"] = predictUsage(currentData.TransactionRate, model)
		case "Network":
			predictions["Network"] = predictUsage(currentData.TransactionRate, model)
		}
	}

	return predictions
}

// trainModel trains a predictive model using the provided data
func trainModel(resourceType string, resourceData, transactionData []float64) ScalingModel {
	x := mat.NewDense(len(transactionData), 1, transactionData)
	y := mat.NewVecDense(len(resourceData), resourceData)

	var theta mat.VecDense
	theta.SolveVec(mat.NewDense(1, 1, nil), x, y)

	return ScalingModel{
		ModelID:    resourceType,
		ModelType:  "LinearRegression",
		Parameters: theta.RawVector().Data,
	}
}

// predictUsage predicts future resource usage based on a model
func predictUsage(transactionRate float64, model ScalingModel) float64 {
	return model.Parameters[0] * transactionRate
}

// extractData extracts specific data points from scaling data
func extractData(data []ScalingData, metricType string) []float64 {
	var extractedData []float64
	for _, d := range data {
		switch metricType {
		case "CPU":
			extractedData = append(extractedData, d.CPUUsage)
		case "Memory":
			extractedData = append(extractedData, d.MemoryUsage)
		case "Network":
			extractedData = append(extractedData, d.NetworkUsage)
		case "Transaction":
			extractedData = append(extractedData, d.TransactionRate)
		}
	}
	return extractedData
}

// SecureDataHash securely hashes data using scrypt
func (slsp *SelfLearningScalingPolicies) SecureDataHash(data []byte, salt []byte) (string, error) {
	hash, err := scrypt.Key(data, salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash), nil
}

// GenerateSalt generates a cryptographically secure salt
func (slsp *SelfLearningScalingPolicies) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
