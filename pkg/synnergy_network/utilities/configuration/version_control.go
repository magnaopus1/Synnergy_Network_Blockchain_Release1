package configuration

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"
	"time"
	"log"
)

// VersionControl manages versioning of configuration files
type VersionControl struct {
	versions map[string][]*ConfigVersion
	mutex    sync.RWMutex
}

// ConfigVersion represents a specific version of a configuration
type ConfigVersion struct {
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
	Config    map[string]interface{} `json:"config"`
}

// NewVersionControl creates a new instance of VersionControl
func NewVersionControl() *VersionControl {
	return &VersionControl{
		versions: make(map[string][]*ConfigVersion),
	}
}

// AddVersion adds a new configuration version
func (vc *VersionControl) AddVersion(name string, version *ConfigVersion) error {
	vc.mutex.Lock()
	defer vc.mutex.Unlock()

	vc.versions[name] = append(vc.versions[name], version)
	log.Printf("Version %s added for configuration %s\n", version.Version, name)

	return nil
}

// GetVersion retrieves a specific version of a configuration
func (vc *VersionControl) GetVersion(name, version string) (*ConfigVersion, error) {
	vc.mutex.RLock()
	defer vc.mutex.RUnlock()

	versions, exists := vc.versions[name]
	if !exists {
		return nil, errors.New("configuration not found")
	}

	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}

	return nil, errors.New("version not found")
}

// ListVersions lists all versions of a specific configuration
func (vc *VersionControl) ListVersions(name string) ([]*ConfigVersion, error) {
	vc.mutex.RLock()
	defer vc.mutex.RUnlock()

	versions, exists := vc.versions[name]
	if !exists {
		return nil, errors.New("configuration not found")
	}

	return versions, nil
}

// SaveVersionToFile saves a specific version of a configuration to a file
func (vc *VersionControl) SaveVersionToFile(name, version, filename string) error {
	vc.mutex.RLock()
	defer vc.mutex.RUnlock()

	configVersion, err := vc.GetVersion(name, version)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(configVersion, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// LoadVersionFromFile loads a specific version of a configuration from a file
func (vc *VersionControl) LoadVersionFromFile(name, filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var configVersion ConfigVersion
	if err := json.Unmarshal(data, &configVersion); err != nil {
		return err
	}

	vc.mutex.Lock()
	defer vc.mutex.Unlock()

	vc.versions[name] = append(vc.versions[name], &configVersion)
	log.Printf("Version %s loaded from file for configuration %s\n", configVersion.Version, name)

	return nil
}

// ValidateConfigVersion validates a configuration version
func ValidateConfigVersion(version *ConfigVersion) error {
	if version.Version == "" {
		return errors.New("version is required")
	}
	if version.Config == nil {
		return errors.New("config is required")
	}
	return nil
}

// InitVersionControl initializes the VersionControl with initial versions
func InitVersionControl(initialVersions map[string][]*ConfigVersion) (*VersionControl, error) {
	vc := NewVersionControl()

	for name, versions := range initialVersions {
		for _, version := range versions {
			if err := ValidateConfigVersion(version); err != nil {
				return nil, err
			}

			if err := vc.AddVersion(name, version); err != nil {
				return nil, err
			}
		}
	}

	return vc, nil
}

// RollbackToVersion rolls back to a specific version of a configuration
func (vc *VersionControl) RollbackToVersion(name, version string) error {
	vc.mutex.RLock()
	defer vc.mutex.RUnlock()

	versions, exists := vc.versions[name]
	if !exists {
		return errors.New("configuration not found")
	}

	for _, v := range versions {
		if v.Version == version {
			// Perform rollback logic here
			log.Printf("Configuration %s rolled back to version %s\n", name, version)
			return nil
		}
	}

	return errors.New("version not found")
}

// Example of usage
func main() {
	// Example initial versions
	initialVersions := map[string][]*ConfigVersion{
		"Development": {
			{
				Timestamp: time.Now(),
				Version:   "v1.0",
				Config: map[string]interface{}{
					"host": "localhost",
					"port": 8080,
				},
			},
		},
		"Production": {
			{
				Timestamp: time.Now(),
				Version:   "v1.0",
				Config: map[string]interface{}{
					"host": "prod.example.com",
					"port": 443,
				},
			},
		},
	}

	// Initialize version control
	vc, err := InitVersionControl(initialVersions)
	if err != nil {
		log.Fatalf("Failed to initialize version control: %v", err)
	}

	// List versions for Development
	versions, err := vc.ListVersions("Development")
	if err != nil {
		log.Fatalf("Failed to list versions: %v", err)
	}

	for _, version := range versions {
		log.Printf("Version: %s, Config: %v\n", version.Version, version.Config)
	}

	// Save a version to file
	if err := vc.SaveVersionToFile("Development", "v1.0", "development_v1.0.json"); err != nil {
		log.Fatalf("Failed to save version to file: %v", err)
	}

	// Load a version from file
	if err := vc.LoadVersionFromFile("Development", "development_v1.0.json"); err != nil {
		log.Fatalf("Failed to load version from file: %v", err)
	}

	// List versions again to verify loading
	versions, err = vc.ListVersions("Development")
	if err != nil {
		log.Fatalf("Failed to list versions: %v", err)
	}

	for _, version := range versions {
		log.Printf("Version: %s, Config: %v\n", version.Version, version.Config)
	}

	// Rollback to a specific version
	if err := vc.RollbackToVersion("Development", "v1.0"); err != nil {
		log.Fatalf("Failed to rollback to version: %v", err)
	}
}
