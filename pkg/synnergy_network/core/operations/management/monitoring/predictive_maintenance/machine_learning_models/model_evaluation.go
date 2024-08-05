package machine_learning_models

import (
	"fmt"
	"log"
	"math"
	"sync"
)

// Model represents a machine learning model
type Model struct {
	ID          string
	Name        string
	Version     string
	Accuracy    float64
	Precision   float64
	Recall      float64
	F1Score     float64
	TrainingSet []DataPoint
	TestSet     []DataPoint
}

// DataPoint represents a single data point for training/testing
type DataPoint struct {
	Features []float64
	Label    float64
}

// ModelEvaluator evaluates the performance of a machine learning model
type ModelEvaluator struct {
	models map[string]*Model
	mu     sync.Mutex
}

// NewModelEvaluator creates a new instance of ModelEvaluator
func NewModelEvaluator() *ModelEvaluator {
	return &ModelEvaluator{
		models: make(map[string]*Model),
	}
}

// AddModel adds a new model to the evaluator
func (e *ModelEvaluator) AddModel(model *Model) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.models[model.ID] = model
}

// EvaluateModel evaluates the performance of a given model using the test set
func (e *ModelEvaluator) EvaluateModel(modelID string) error {
	e.mu.Lock()
	model, exists := e.models[modelID]
	e.mu.Unlock()

	if !exists {
		return fmt.Errorf("model with ID %s not found", modelID)
	}

	truePositives := 0
	falsePositives := 0
	trueNegatives := 0
	falseNegatives := 0

	for _, dp := range model.TestSet {
		predicted := e.predict(model, dp.Features)
		if predicted == dp.Label {
			if predicted == 1.0 {
				truePositives++
			} else {
				trueNegatives++
			}
		} else {
			if predicted == 1.0 {
				falsePositives++
			} else {
				falseNegatives++
			}
		}
	}

	model.Accuracy = float64(truePositives+trueNegatives) / float64(len(model.TestSet))
	model.Precision = float64(truePositives) / float64(truePositives+falsePositives)
	model.Recall = float64(truePositives) / float64(truePositives+falseNegatives)
	model.F1Score = 2 * ((model.Precision * model.Recall) / (model.Precision + model.Recall))

	e.mu.Lock()
	e.models[model.ID] = model
	e.mu.Unlock()

	return nil
}

// predict makes a prediction for a given data point
func (e *ModelEvaluator) predict(model *Model, features []float64) float64 {
	// Placeholder for actual prediction logic
	// Replace with model-specific prediction implementation
	return math.Round(features[0]) // Example prediction logic
}

// EvaluateAllModels evaluates the performance of all models in the evaluator
func (e *ModelEvaluator) EvaluateAllModels() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for modelID := range e.models {
		if err := e.EvaluateModel(modelID); err != nil {
			log.Printf("Error evaluating model %s: %v", modelID, err)
		}
	}
}

// DisplayMetrics displays the evaluation metrics of a model
func (e *ModelEvaluator) DisplayMetrics(modelID string) {
	e.mu.Lock()
	model, exists := e.models[modelID]
	e.mu.Unlock()

	if !exists {
		log.Printf("Model with ID %s not found", modelID)
		return
	}

	fmt.Printf("Model ID: %s\n", model.ID)
	fmt.Printf("Model Name: %s\n", model.Name)
	fmt.Printf("Version: %s\n", model.Version)
	fmt.Printf("Accuracy: %.2f\n", model.Accuracy)
	fmt.Printf("Precision: %.2f\n", model.Precision)
	fmt.Printf("Recall: %.2f\n", model.Recall)
	fmt.Printf("F1 Score: %.2f\n", model.F1Score)
}

// RemoveModel removes a model from the evaluator
func (e *ModelEvaluator) RemoveModel(modelID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.models, modelID)
}

