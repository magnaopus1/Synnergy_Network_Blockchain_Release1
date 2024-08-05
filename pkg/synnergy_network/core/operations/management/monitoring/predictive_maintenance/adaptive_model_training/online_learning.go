package adaptive_model_training

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat"
	"gonum.org/v1/gonum/floats"

	"github.com/synnergy_network/encryption"
	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/monitoring"
)

// Model represents a machine learning model used for predictive maintenance.
type Model struct {
	Weights      *mat.Dense
	LastUpdated  time.Time
	UpdateMutex  sync.Mutex
	ModelPath    string
}

// NewModel initializes a new Model.
func NewModel(modelPath string) (*Model, error) {
	model := &Model{
		Weights:     nil,
		LastUpdated: time.Now(),
		ModelPath:   modelPath,
	}
	if err := model.LoadModel(); err != nil {
		return nil, err
	}
	return model, nil
}

// LoadModel loads the model weights from a file.
func (m *Model) LoadModel() error {
	m.UpdateMutex.Lock()
	defer m.UpdateMutex.Unlock()

	if _, err := os.Stat(m.ModelPath); os.IsNotExist(err) {
		return errors.New("model file does not exist")
	}

	modelData, err := ioutil.ReadFile(m.ModelPath)
	if err != nil {
		return fmt.Errorf("failed to read model file: %v", err)
	}

	var weights [][]float64
	if err := json.Unmarshal(modelData, &weights); err != nil {
		return fmt.Errorf("failed to unmarshal model data: %v", err)
	}

	r, c := len(weights), len(weights[0])
	m.Weights = mat.NewDense(r, c, nil)
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			m.Weights.Set(i, j, weights[i][j])
		}
	}

	return nil
}

// SaveModel saves the model weights to a file.
func (m *Model) SaveModel() error {
	m.UpdateMutex.Lock()
	defer m.UpdateMutex.Unlock()

	weights := make([][]float64, m.Weights.RawMatrix().Rows)
	for i := 0; i < len(weights); i++ {
		weights[i] = make([]float64, m.Weights.RawMatrix().Cols)
		for j := 0; j < len(weights[i]); j++ {
			weights[i][j] = m.Weights.At(i, j)
		}
	}

	modelData, err := json.Marshal(weights)
	if err != nil {
		return fmt.Errorf("failed to marshal model data: %v", err)
	}

	if err := ioutil.WriteFile(m.ModelPath, modelData, 0644); err != nil {
		return fmt.Errorf("failed to write model file: %v", err)
	}

	m.LastUpdated = time.Now()
	return nil
}

// UpdateModel updates the model weights using new data.
func (m *Model) UpdateModel(newData *mat.Dense, learningRate float64) error {
	m.UpdateMutex.Lock()
	defer m.UpdateMutex.Unlock()

	r, c := m.Weights.Dims()
	if newData.RawMatrix().Rows != r || newData.RawMatrix().Cols != c {
		return errors.New("new data dimensions do not match model dimensions")
	}

	// Update model weights using a simple gradient descent approach.
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			gradient := newData.At(i, j) - m.Weights.At(i, j)
			m.Weights.Set(i, j, m.Weights.At(i, j)+learningRate*gradient)
		}
	}

	if err := m.SaveModel(); err != nil {
		return err
	}

	return nil
}

// Predict makes predictions using the current model weights.
func (m *Model) Predict(input *mat.Dense) (*mat.Dense, error) {
	m.UpdateMutex.Lock()
	defer m.UpdateMutex.Unlock()

	_, inputCols := input.Dims()
	weightsRows, weightsCols := m.Weights.Dims()

	if inputCols != weightsRows {
		return nil, errors.New("input dimensions do not match model dimensions")
	}

	output := mat.NewDense(input.RawMatrix().Rows, weightsCols, nil)
	output.Mul(input, m.Weights)
	return output, nil
}

// TrainModel trains the model using historical and real-time data.
func (m *Model) TrainModel(historicalData, realTimeData *mat.Dense, learningRate float64) error {
	combinedData := mat.NewDense(historicalData.RawMatrix().Rows+realTimeData.RawMatrix().Rows, historicalData.RawMatrix().Cols, nil)
	combinedData.Stack(historicalData, realTimeData)

	means := stat.Mean(combinedData.RawRowView(0), nil)
	stdDevs := stat.StdDev(combinedData.RawRowView(0), nil)

	// Normalize data
	for i := 0; i < combinedData.RawMatrix().Rows; i++ {
		row := combinedData.RawRowView(i)
		floats.SubTo(row, row, means)
		floats.DivTo(row, row, stdDevs)
		combinedData.SetRow(i, row)
	}

	if err := m.UpdateModel(combinedData, learningRate); err != nil {
		return err
	}

	return nil
}

// EncryptModel encrypts the model weights using AES encryption.
func (m *Model) EncryptModel(key []byte) ([]byte, error) {
	modelData, err := json.Marshal(m.Weights)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal model data: %v", err)
	}

	encryptedData, err := encryption.AESEncrypt(modelData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt model data: %v", err)
	}

	return encryptedData, nil
}

// DecryptModel decrypts the model weights using AES encryption.
func (m *Model) DecryptModel(encryptedData, key []byte) error {
	modelData, err := encryption.AESDecrypt(encryptedData, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt model data: %v", err)
	}

	var weights [][]float64
	if err := json.Unmarshal(modelData, &weights); err != nil {
		return fmt.Errorf("failed to unmarshal model data: %v", err)
	}

	r, c := len(weights), len(weights[0])
	m.Weights = mat.NewDense(r, c, nil)
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			m.Weights.Set(i, j, weights[i][j])
		}
	}

	return nil
}

// BlockchainLogging logs model update activities to the blockchain for transparency and auditability.
func (m *Model) BlockchainLogging(activity string) error {
	logData := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"activity":  activity,
		"model":     m.ModelPath,
	}
	logJSON, err := json.Marshal(logData)
	if err != nil {
		return fmt.Errorf("failed to marshal log data: %v", err)
	}

	if err := blockchain.LogActivity(logJSON); err != nil {
		return fmt.Errorf("failed to log activity to blockchain: %v", err)
	}

	return nil
}

// OnlineLearning continuously learns from new data to update the model.
func (m *Model) OnlineLearning(newDataStream <-chan *mat.Dense, learningRate float64) {
	for newData := range newDataStream {
		if err := m.UpdateModel(newData, learningRate); err != nil {
			log.Printf("Failed to update model: %v", err)
		}
		if err := m.BlockchainLogging("Model updated via online learning"); err != nil {
			log.Printf("Failed to log activity to blockchain: %v", err)
		}
	}
}

// StartOnlineLearning starts the online learning process.
func (m *Model) StartOnlineLearning(newDataStream <-chan *mat.Dense, learningRate float64) {
	go m.OnlineLearning(newDataStream, learningRate)
}
