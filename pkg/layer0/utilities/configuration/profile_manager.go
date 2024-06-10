package configuration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
)

// Profile represents a configuration profile
type Profile struct {
	Name   string `json:"name"`
	Config map[string]interface{} `json:"config"`
}

// ProfileManager manages multiple configuration profiles
type ProfileManager struct {
	profiles map[string]*Profile
	mutex    sync.RWMutex
}

// NewProfileManager creates a new instance of ProfileManager
func NewProfileManager() *ProfileManager {
	return &ProfileManager{
		profiles: make(map[string]*Profile),
	}
}

// AddProfile adds a new profile to the manager
func (pm *ProfileManager) AddProfile(profile *Profile) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.profiles[profile.Name]; exists {
		return errors.New("profile already exists")
	}

	pm.profiles[profile.Name] = profile
	log.Printf("Profile %s added\n", profile.Name)

	return nil
}

// UpdateProfile updates an existing profile
func (pm *ProfileManager) UpdateProfile(profile *Profile) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.profiles[profile.Name]; !exists {
		return errors.New("profile does not exist")
	}

	pm.profiles[profile.Name] = profile
	log.Printf("Profile %s updated\n", profile.Name)

	return nil
}

// RemoveProfile removes a profile by name
func (pm *ProfileManager) RemoveProfile(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.profiles[name]; !exists {
		return errors.New("profile does not exist")
	}

	delete(pm.profiles, name)
	log.Printf("Profile %s removed\n", name)

	return nil
}

// GetProfile retrieves a profile by name
func (pm *ProfileManager) GetProfile(name string) (*Profile, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	profile, exists := pm.profiles[name]
	if !exists {
		return nil, errors.New("profile not found")
	}

	return profile, nil
}

// ListProfiles lists all available profiles
func (pm *ProfileManager) ListProfiles() []*Profile {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var profiles []*Profile
	for _, profile := range pm.profiles {
		profiles = append(profiles, profile)
	}

	return profiles
}

// SaveProfileToFile saves a profile to a file
func (pm *ProfileManager) SaveProfileToFile(name, filename string) error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	profile, exists := pm.profiles[name]
	if !exists {
		return errors.New("profile not found")
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// LoadProfileFromFile loads a profile from a file
func (pm *ProfileManager) LoadProfileFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return err
	}

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.profiles[profile.Name] = &profile
	log.Printf("Profile %s loaded from file\n", profile.Name)

	return nil
}

// ValidateProfile validates the configuration of a profile
func ValidateProfile(profile *Profile) error {
	if profile.Name == "" {
		return errors.New("profile name is required")
	}
	if profile.Config == nil {
		return errors.New("profile config is required")
	}
	return nil
}

// InitProfileManager initializes the ProfileManager with initial profiles
func InitProfileManager(initialProfiles []*Profile) (*ProfileManager, error) {
	manager := NewProfileManager()

	for _, profile := range initialProfiles {
		if err := ValidateProfile(profile); err != nil {
			return nil, err
		}

		if err := manager.AddProfile(profile); err != nil {
			return nil, err
		}
	}

	return manager, nil
}

// Example of usage
func main() {
	// Example profiles
	profiles := []*Profile{
		{
			Name: "Development",
			Config: map[string]interface{}{
				"host": "localhost",
				"port": 8080,
			},
		},
		{
			Name: "Production",
			Config: map[string]interface{}{
				"host": "prod.example.com",
				"port": 443,
			},
		},
	}

	// Initialize profile manager
	manager, err := InitProfileManager(profiles)
	if err != nil {
		log.Fatalf("Failed to initialize profile manager: %v", err)
	}

	// List profiles
	for _, profile := range manager.ListProfiles() {
		fmt.Printf("Profile: %s, Config: %v\n", profile.Name, profile.Config)
	}

	// Save a profile to file
	if err := manager.SaveProfileToFile("Development", "development_profile.json"); err != nil {
		log.Fatalf("Failed to save profile to file: %v", err)
	}

	// Load a profile from file
	if err := manager.LoadProfileFromFile("development_profile.json"); err != nil {
		log.Fatalf("Failed to load profile from file: %v", err)
	}

	// List profiles again to verify loading
	for _, profile := range manager.ListProfiles() {
		fmt.Printf("Profile: %s, Config: %v\n", profile.Name, profile.Config)
	}
}
