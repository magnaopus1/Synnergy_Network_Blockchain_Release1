package machine_learning_models

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/predictive_maintenance/data_collection"
	"github.com/synthron_blockchain_final/pkg/security"
	"gonum.org/v1/gonum/floats"
	"gonum.org/v1/gonum/stat"
)

// ModelEvaluator handles the evaluation of machine learning models used in predictive maintenance.
type ModelEvaluator struct {
	models             map[string]Model
	evaluationResults  map[string]EvaluationResult
	secureCommunicator *security.SecureCommunicator
}

// Model represents a machine learning model with methods for prediction and evaluation.
type Model interface {
	Predict(data []float64) ([]float64, error)
	Evaluate(testData []float64, testLabels []float64) (EvaluationResult, error)
}

// EvaluationResult holds the results of model evaluation.
type EvaluationResult struct {
	MSE       float64 `json:"mse"`
	MAE       float64 `json:"mae"`
	RMSE      float64 `json:"rmse"`
	R2        float64 `json:"r2"`
	Encrypted string  `json:"encrypted"`
}

// NewModelEvaluator creates a new instance of ModelEvaluator.
func NewModelEvaluator() (*ModelEvaluator, error) {
	secureComm, err := security.NewSecureCommunicator("securepassphrase")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secure communicator: %w", err)
	}

	return &ModelEvaluator{
		models:             make(map[string]Model),
		evaluationResults:  make(map[string]EvaluationResult),
		secureCommunicator: secureComm,
	}, nil
}

// RegisterModel registers a machine learning model for evaluation.
func (me *ModelEvaluator) RegisterModel(name string, model Model) {
	me.models[name] = model
}

// EvaluateModels evaluates all registered models using the provided test data and labels.
func (me *ModelEvaluator) EvaluateModels(testData []float64, testLabels []float64) error {
	for name, model := range me.models {
		result, err := model.Evaluate(testData, testLabels)
		if err != nil {
			return fmt.Errorf("failed to evaluate model %s: %w", name, err)
		}
		encryptedResult, err := me.secureCommunicator.EncryptData(result)
		if err != nil {
			return fmt.Errorf("failed to encrypt evaluation result for model %s: %w", name, err)
		}
		result.Encrypted = encryptedResult
		me.evaluationResults[name] = result
	}
	return nil
}

// SaveResults saves the evaluation results to a JSON file.
func (me *ModelEvaluator) SaveResults(filename string) error {
	data, err := json.Marshal(me.evaluationResults)
	if err != nil {
		return fmt.Errorf("failed to marshal evaluation results: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write evaluation results to file: %w", err)
	}
	return nil
}

// BasicModel is a simple implementation of the Model interface for demonstration purposes.
type BasicModel struct{}

// Predict performs prediction using the BasicModel.
func (bm *BasicModel) Predict(data []float64) ([]float64, error) {
	// Placeholder prediction logic
	return data, nil
}

// Evaluate evaluates the BasicModel using mean squared error, mean absolute error, RMSE, and R-squared metrics.
func (bm *BasicModel) Evaluate(testData []float64, testLabels []float64) (EvaluationResult, error) {
	if len(testData) != len(testLabels) {
		return EvaluationResult{}, errors.New("test data and labels must have the same length")
	}

	predictions, err := bm.Predict(testData)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("failed to predict: %w", err)
	}

	mse := stat.MSE(predictions, testLabels, nil)
	mae := stat.MAE(predictions, testLabels, nil)
	rmse := math.Sqrt(mse)
	r2 := stat.RSquared(predictions, testLabels, nil)

	return EvaluationResult{
		MSE:  mse,
		MAE:  mae,
		RMSE: rmse,
		R2:   r2,
	}, nil
}

// Example usage
func main() {
	evaluator, err := NewModelEvaluator()
	if err != nil {
		fmt.Printf("Error creating ModelEvaluator: %v\n", err)
		return
	}

	basicModel := &BasicModel{}
	evaluator.RegisterModel("BasicModel", basicModel)

	testData := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	testLabels := []float64{1.1, 2.1, 3.1, 4.1, 5.1}

	err = evaluator.EvaluateModels(testData, testLabels)
	if err != nil {
		fmt.Printf("Error evaluating models: %v\n", err)
		return
	}

	err = evaluator.SaveResults("evaluation_results.json")
	if err != nil {
		fmt.Printf("Error saving results: %v\n", err)
		return
	}

	fmt.Println("Model evaluation completed and results saved.")
}
