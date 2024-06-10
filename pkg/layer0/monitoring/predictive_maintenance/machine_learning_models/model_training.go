package machine_learning_models

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/predictive_maintenance/data_collection"
	"github.com/synthron_blockchain_final/pkg/security"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat"
)

// ModelTrainer handles the training of machine learning models used in predictive maintenance.
type ModelTrainer struct {
	models             map[string]Model
	trainingData       *mat.Dense
	trainingLabels     *mat.Dense
	secureCommunicator *security.SecureCommunicator
}

// Model represents a machine learning model with methods for training and prediction.
type Model interface {
	Train(data, labels *mat.Dense) error
	Predict(data *mat.Dense) (*mat.Dense, error)
	SaveModel(filename string) error
	LoadModel(filename string) error
}

// NewModelTrainer creates a new instance of ModelTrainer.
func NewModelTrainer() (*ModelTrainer, error) {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secure communicator: %w", err)
	}

	return &ModelTrainer{
		models:             make(map[string]Model),
		secureCommunicator: secureComm,
	}, nil
}

// RegisterModel registers a machine learning model for training.
func (mt *ModelTrainer) RegisterModel(name string, model Model) {
	mt.models[name] = model
}

// LoadTrainingData loads training data and labels from files.
func (mt *ModelTrainer) LoadTrainingData(dataFile, labelsFile string) error {
	data, err := ioutil.ReadFile(dataFile)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}
	labels, err := ioutil.ReadFile(labelsFile)
	if err != nil {
		return fmt.Errorf("failed to read labels file: %w", err)
	}

	dataMatrix, err := mt.secureCommunicator.DecryptDataToMatrix(data)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}
	labelsMatrix, err := mt.secureCommunicator.DecryptDataToMatrix(labels)
	if err != nil {
		return fmt.Errorf("failed to decrypt labels: %w", err)
	}

	mt.trainingData = dataMatrix
	mt.trainingLabels = labelsMatrix
	return nil
}

// TrainModels trains all registered models using the loaded training data.
func (mt *ModelTrainer) TrainModels() error {
	if mt.trainingData == nil || mt.trainingLabels == nil {
		return errors.New("training data or labels not loaded")
	}

	for name, model := range mt.models {
		err := model.Train(mt.trainingData, mt.trainingLabels)
		if err != nil {
			return fmt.Errorf("failed to train model %s: %w", name, err)
		}
	}
	return nil
}

// SaveModels saves all trained models to files.
func (mt *ModelTrainer) SaveModels() error {
	for name, model := range mt.models {
		filename := fmt.Sprintf("%s_model.json", name)
		err := model.SaveModel(filename)
		if err != nil {
			return fmt.Errorf("failed to save model %s: %w", name, err)
		}
	}
	return nil
}

// LoadModels loads all models from files.
func (mt *ModelTrainer) LoadModels() error {
	for name, model := range mt.models {
		filename := fmt.Sprintf("%s_model.json", name)
		err := model.LoadModel(filename)
		if err != nil {
			return fmt.Errorf("failed to load model %s: %w", name, err)
		}
	}
	return nil
}

// BasicModel is a simple implementation of the Model interface for demonstration purposes.
type BasicModel struct {
	weights *mat.Dense
}

// Train trains the BasicModel using simple linear regression.
func (bm *BasicModel) Train(data, labels *mat.Dense) error {
	rows, cols := data.Dims()
	_, labelCols := labels.Dims()

	bm.weights = mat.NewDense(cols, labelCols, nil)
	XTX := mat.NewDense(cols, cols, nil)
	XTY := mat.NewDense(cols, labelCols, nil)

	XT := data.T()
	XTX.Mul(XT, data)
	XTY.Mul(XT, labels)

	err := XTX.Inverse(XTX)
	if err != nil {
		return fmt.Errorf("failed to invert XTX matrix: %w", err)
	}

	bm.weights.Mul(XTX, XTY)
	return nil
}

// Predict performs prediction using the BasicModel.
func (bm *BasicModel) Predict(data *mat.Dense) (*mat.Dense, error) {
	var result mat.Dense
	result.Mul(data, bm.weights)
	return &result, nil
}

// SaveModel saves the BasicModel to a file.
func (bm *BasicModel) SaveModel(filename string) error {
	weightsBytes, err := json.Marshal(bm.weights)
	if err != nil {
		return fmt.Errorf("failed to marshal weights: %w", err)
	}
	return ioutil.WriteFile(filename, weightsBytes, 0644)
}

// LoadModel loads the BasicModel from a file.
func (bm *BasicModel) LoadModel(filename string) error {
	weightsBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read model file: %w", err)
	}
	err = json.Unmarshal(weightsBytes, bm.weights)
	if err != nil {
		return fmt.Errorf("failed to unmarshal weights: %w", err)
	}
	return nil
}

// Example usage
func main() {
	rand.Seed(time.Now().UnixNano())

	trainer, err := NewModelTrainer()
	if err != nil {
		fmt.Printf("Error creating ModelTrainer: %v\n", err)
		return
	}

	basicModel := &BasicModel{}
	trainer.RegisterModel("BasicModel", basicModel)

	err = trainer.LoadTrainingData("training_data.json", "training_labels.json")
	if err != nil {
		fmt.Printf("Error loading training data: %v\n", err)
		return
	}

	err = trainer.TrainModels()
	if err != nil {
		fmt.Printf("Error training models: %v\n", err)
		return
	}

	err = trainer.SaveModels()
	if err != nil {
		fmt.Printf("Error saving models: %v\n", err)
		return
	}

	fmt.Println("Model training completed and models saved.")
}
