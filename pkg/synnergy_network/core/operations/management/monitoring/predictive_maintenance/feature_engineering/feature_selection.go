package feature_engineering

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/utils"
)

// Feature represents a single feature with its properties
type Feature struct {
	Name       string
	Importance float64
	Selected   bool
}

// FeatureSelectionConfig holds the configuration for the feature selection process
type FeatureSelectionConfig struct {
	MaxFeatures      int
	SelectionMethod  string
	ImportanceThresh float64
}

// FeatureSelector implements feature selection logic
type FeatureSelector struct {
	Features []Feature
	Config   FeatureSelectionConfig
}

// NewFeatureSelector initializes a new FeatureSelector
func NewFeatureSelector(features []Feature, config FeatureSelectionConfig) *FeatureSelector {
	return &FeatureSelector{
		Features: features,
		Config:   config,
	}
}

// RankFeatures ranks the features based on the selection method
func (fs *FeatureSelector) RankFeatures() error {
	switch fs.Config.SelectionMethod {
	case "importance":
		fs.rankByImportance()
	case "random":
		fs.rankRandomly()
	default:
		return errors.New("unknown selection method")
	}
	return nil
}

// rankByImportance ranks features based on their importance
func (fs *FeatureSelector) rankByImportance() {
	for i := range fs.Features {
		fs.Features[i].Importance = fs.calculateImportance(fs.Features[i])
	}
	utils.SortByImportance(fs.Features)
}

// rankRandomly ranks features randomly
func (fs *FeatureSelector) rankRandomly() {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(fs.Features), func(i, j int) {
		fs.Features[i], fs.Features[j] = fs.Features[j], fs.Features[i]
	})
}

// calculateImportance calculates the importance of a feature
func (fs *FeatureSelector) calculateImportance(feature Feature) float64 {
	// Implement a sophisticated AI-driven feature importance calculation
	// For demonstration, using a random importance value
	return rand.Float64()
}

// SelectFeatures selects the top N features based on the ranking
func (fs *FeatureSelector) SelectFeatures() ([]Feature, error) {
	if len(fs.Features) == 0 {
		return nil, errors.New("no features to select from")
	}

	selectedFeatures := []Feature{}
	for _, feature := range fs.Features {
		if len(selectedFeatures) >= fs.Config.MaxFeatures {
			break
		}
		if feature.Importance >= fs.Config.ImportanceThresh {
			feature.Selected = true
			selectedFeatures = append(selectedFeatures, feature)
		}
	}

	if len(selectedFeatures) == 0 {
		return nil, errors.New("no features selected, check importance threshold")
	}
	return selectedFeatures, nil
}

// LogFeatureSelection logs the selected features to the blockchain for transparency and auditability
func (fs *FeatureSelector) LogFeatureSelection(selectedFeatures []Feature) error {
	// Create a log entry
	logEntry := fmt.Sprintf("Selected Features: %v", selectedFeatures)
	// Log the entry to the blockchain
	err := blockchain.LogToBlockchain(logEntry)
	if err != nil {
		return errors.New("failed to log feature selection to blockchain")
	}
	return nil
}

func main() {
	// Example usage
	features := []Feature{
		{"Feature1", 0.0, false},
		{"Feature2", 0.0, false},
		{"Feature3", 0.0, false},
	}

	config := FeatureSelectionConfig{
		MaxFeatures:      2,
		SelectionMethod:  "importance",
		ImportanceThresh: 0.5,
	}

	selector := NewFeatureSelector(features, config)
	err := selector.RankFeatures()
	if err != nil {
		fmt.Println("Error ranking features:", err)
		return
	}

	selectedFeatures, err := selector.SelectFeatures()
	if err != nil {
		fmt.Println("Error selecting features:", err)
		return
	}

	err = selector.LogFeatureSelection(selectedFeatures)
	if err != nil {
		fmt.Println("Error logging feature selection:", err)
		return
	}

	fmt.Println("Selected features successfully logged to blockchain.")
}
