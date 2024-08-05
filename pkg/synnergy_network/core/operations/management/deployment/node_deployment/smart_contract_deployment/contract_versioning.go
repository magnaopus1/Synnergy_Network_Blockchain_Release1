package smart_contract_deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

// ContractVersioning is responsible for managing versions of smart contracts
type ContractVersioning struct {
	versionDir string
	mu         sync.Mutex
}

// ContractInfo holds information about a smart contract
type ContractInfo struct {
	Version     string `json:"version"`
	Description string `json:"description"`
	Hash        string `json:"hash"`
}

// NewContractVersioning creates a new ContractVersioning instance
func NewContractVersioning(versionDir string) *ContractVersioning {
	return &ContractVersioning{
		versionDir: versionDir,
	}
}

// SaveContractVersion saves a new version of a smart contract
func (cv *ContractVersioning) SaveContractVersion(contractPath, version, description string) (string, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	contractBin, err := ioutil.ReadFile(contractPath)
	if err != nil {
		return "", fmt.Errorf("failed to read contract binary: %w", err)
	}

	hash := sha256.Sum256(contractBin)
	hashStr := hex.EncodeToString(hash[:])

	contractInfo := ContractInfo{
		Version:     version,
		Description: description,
		Hash:        hashStr,
	}

	infoPath := filepath.Join(cv.versionDir, version+".json")
	infoData, err := json.Marshal(contractInfo)
	if err != nil {
		return "", fmt.Errorf("failed to marshal contract info: %w", err)
	}

	err = ioutil.WriteFile(infoPath, infoData, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write contract info: %w", err)
	}

	return hashStr, nil
}

// GetContractVersion retrieves information about a specific version of a smart contract
func (cv *ContractVersioning) GetContractVersion(version string) (*ContractInfo, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	infoPath := filepath.Join(cv.versionDir, version+".json")
	infoData, err := ioutil.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read contract info: %w", err)
	}

	var contractInfo ContractInfo
	err = json.Unmarshal(infoData, &contractInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal contract info: %w", err)
	}

	return &contractInfo, nil
}

// ListContractVersions lists all the versions of smart contracts
func (cv *ContractVersioning) ListContractVersions() ([]ContractInfo, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	var versions []ContractInfo

	files, err := ioutil.ReadDir(cv.versionDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read version directory: %w", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			infoData, err := ioutil.ReadFile(filepath.Join(cv.versionDir, file.Name()))
			if err != nil {
				return nil, fmt.Errorf("failed to read contract info: %w", err)
			}

			var contractInfo ContractInfo
			err = json.Unmarshal(infoData, &contractInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal contract info: %w", err)
			}

			versions = append(versions, contractInfo)
		}
	}

	return versions, nil
}

// VerifyContractVersion verifies the integrity of a smart contract version
func (cv *ContractVersioning) VerifyContractVersion(version string, contractPath string) (bool, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	contractBin, err := ioutil.ReadFile(contractPath)
	if err != nil {
		return false, fmt.Errorf("failed to read contract binary: %w", err)
	}

	hash := sha256.Sum256(contractBin)
	hashStr := hex.EncodeToString(hash[:])

	contractInfo, err := cv.GetContractVersion(version)
	if err != nil {
		return false, fmt.Errorf("failed to get contract version info: %w", err)
	}

	if contractInfo.Hash != hashStr {
		return false, errors.New("contract version hash mismatch")
	}

	return true, nil
}

// DeleteContractVersion deletes a specific version of a smart contract
func (cv *ContractVersioning) DeleteContractVersion(version string) error {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	infoPath := filepath.Join(cv.versionDir, version+".json")
	err := os.Remove(infoPath)
	if err != nil {
		return fmt.Errorf("failed to delete contract version: %w", err)
	}

	return nil
}
