package smart_contract_deployment

import (
	"fmt"
	"time"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"log"
	"path/filepath"
	"io/ioutil"
	"encoding/json"
)

// SmartContractVersion represents a versioned smart contract
type SmartContractVersion struct {
	Version     string `json:"version"`
	Hash        string `json:"hash"`
	Timestamp   time.Time `json:"timestamp"`
	Author      string `json:"author"`
	Description string `json:"description"`
}

// VersioningManager handles the versioning and auditing of smart contracts
type VersioningManager struct {
	versionsDir string
}

// NewVersioningManager creates a new instance of VersioningManager
func NewVersioningManager(versionsDir string) *VersioningManager {
	if _, err := os.Stat(versionsDir); os.IsNotExist(err) {
		os.MkdirAll(versionsDir, os.ModePerm)
	}
	return &VersioningManager{versionsDir: versionsDir}
}

// SaveNewVersion saves a new version of the smart contract
func (vm *VersioningManager) SaveNewVersion(filePath, author, description string) (*SmartContractVersion, error) {
	contractCode, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read smart contract file: %v", err)
	}

	hash := sha256.Sum256(contractCode)
	version := SmartContractVersion{
		Version:     generateVersionHash(contractCode),
		Hash:        hex.EncodeToString(hash[:]),
		Timestamp:   time.Now(),
		Author:      author,
		Description: description,
	}

	versionFileName := filepath.Join(vm.versionsDir, version.Version+".json")
	versionFile, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal version data: %v", err)
	}

	err = ioutil.WriteFile(versionFileName, versionFile, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write version file: %v", err)
	}

	return &version, nil
}

// LoadVersion loads a specific version of the smart contract
func (vm *VersioningManager) LoadVersion(version string) (*SmartContractVersion, error) {
	versionFileName := filepath.Join(vm.versionsDir, version+".json")
	versionFile, err := ioutil.ReadFile(versionFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read version file: %v", err)
	}

	var scVersion SmartContractVersion
	err = json.Unmarshal(versionFile, &scVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal version data: %v", err)
	}

	return &scVersion, nil
}

// ListVersions lists all saved versions of the smart contract
func (vm *VersioningManager) ListVersions() ([]SmartContractVersion, error) {
	var versions []SmartContractVersion
	err := filepath.Walk(vm.versionsDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			versionFile, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var scVersion SmartContractVersion
			err = json.Unmarshal(versionFile, &scVersion)
			if err != nil {
				return err
			}

			versions = append(versions, scVersion)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %v", err)
	}

	return versions, nil
}

// generateVersionHash generates a version hash based on the contract code
func generateVersionHash(code []byte) string {
	hash := sha256.Sum256(code)
	return hex.EncodeToString(hash[:])
}

func main() {
	// Example usage
	vm := NewVersioningManager("./versions")

	// Save a new version
	version, err := vm.SaveNewVersion("path/to/smart_contract.sol", "AuthorName", "Initial deployment")
	if err != nil {
		log.Fatalf("Error saving new version: %v", err)
	}
	fmt.Printf("New version saved: %v\n", version)

	// Load a specific version
	loadedVersion, err := vm.LoadVersion(version.Version)
	if err != nil {
		log.Fatalf("Error loading version: %v", err)
	}
	fmt.Printf("Loaded version: %v\n", loadedVersion)

	// List all versions
	versions, err := vm.ListVersions()
	if err != nil {
		log.Fatalf("Error listing versions: %v", err)
	}
	fmt.Printf("All versions: %v\n", versions)
}
