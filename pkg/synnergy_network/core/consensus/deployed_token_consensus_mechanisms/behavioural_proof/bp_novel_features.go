package behavioural_proof

import (
	"sync"
)

// NovelFeaturesManager manages the integration of new features and technologies into the consensus mechanism.
type NovelFeaturesManager struct {
	mutex   sync.RWMutex
	features map[string]Feature
}

// Feature defines the structure for novel features within the network.
type Feature struct {
	Name        string
	Description string
	Enabled     bool
	Activation  func() error
}

// NewNovelFeaturesManager creates a new manager for novel features.
func NewNovelFeaturesManager() *NovelFeaturesManager {
	return &NovelFeaturesManager{
		features: make(map[string]Feature),
	}
}

// RegisterFeature registers a new feature within the network's consensus mechanism.
func (nm *NovelFeaturesManager) RegisterFeature(name, description string, activation func() error) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	nm.features[name] = Feature{
		Name:        name,
		Description: description,
		Enabled:     false,
		Activation:  activation,
	}
}

// EnableFeature enables a registered feature by name.
func (nm *NovelFeaturesManager) EnableFeature(name string) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	feature, exists := nm.features[name]
	if !exists {
		return fmt.Errorf("feature %s not found", name)
	}

	if feature.Enabled {
		return fmt.Errorf("feature %s is already enabled", name)
	}

	err := feature.Activation()
	if err != nil {
		return err
	}

	feature.Enabled = true
	nm.features[name] = feature
	return nil
}

// GetFeatureInfo returns the details of a feature.
func (nm *NovelFeaturesManager) GetFeatureInfo(name string) (Feature, bool) {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	feature, exists := nm.features[name]
	return feature, exists
}

// ListFeatures lists all features within the system.
func (nm *NovelFeaturesManager) ListFeatures() []Feature {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()

	list := make([]Feature, 0, len(nm.features))
	for _, feature := range nm.features {
		list = append(list, feature)
	}
	return list
}
