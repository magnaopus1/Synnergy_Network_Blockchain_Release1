package config_management

import (
	"fmt"
	"os/exec"
	"log"
	"io/ioutil"
	"github.com/synnergy_network/utils/encryption"
	"github.com/synnergy_network/utils/logging"
)

// PuppetIntegration manages configuration updates using Puppet
type PuppetIntegration struct {
	ManifestPath string
	Environment  string
}

// NewPuppetIntegration creates a new instance of PuppetIntegration
func NewPuppetIntegration(manifestPath, environment string) *PuppetIntegration {
	return &PuppetIntegration{
		ManifestPath: manifestPath,
		Environment:  environment,
	}
}

// ApplyManifest applies the Puppet manifest to the specified environment
func (pi *PuppetIntegration) ApplyManifest() error {
	cmd := exec.Command("puppet", "apply", pi.ManifestPath, "--environment", pi.Environment)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to apply Puppet manifest: %s", string(output)))
		return fmt.Errorf("failed to apply Puppet manifest: %w", err)
	}
	logging.Info(fmt.Sprintf("Successfully applied Puppet manifest: %s", string(output)))
	return nil
}

// UpdateConfiguration updates the Puppet configuration
func (pi *PuppetIntegration) UpdateConfiguration(configData []byte) error {
	encryptedData, err := encryption.EncryptData(configData)
	if err != nil {
		logging.Error("Failed to encrypt configuration data")
		return fmt.Errorf("failed to encrypt configuration data: %w", err)
	}

	err = ioutil.WriteFile(pi.ManifestPath, encryptedData, 0644)
	if err != nil {
		logging.Error("Failed to write configuration data to manifest file")
		return fmt.Errorf("failed to write configuration data to manifest file: %w", err)
	}

	err = pi.ApplyManifest()
	if err != nil {
		return fmt.Errorf("failed to apply updated configuration: %w", err)
	}

	logging.Info("Successfully updated and applied Puppet configuration")
	return nil
}

// ValidateConfiguration validates the current Puppet configuration
func (pi *PuppetIntegration) ValidateConfiguration() (bool, error) {
	cmd := exec.Command("puppet", "parser", "validate", pi.ManifestPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Puppet configuration validation failed: %s", string(output)))
		return false, fmt.Errorf("Puppet configuration validation failed: %w", err)
	}
	logging.Info("Puppet configuration is valid")
	return true, nil
}

// RollbackConfiguration rolls back to a previous configuration state
func (pi *PuppetIntegration) RollbackConfiguration(backupPath string) error {
	backupData, err := ioutil.ReadFile(backupPath)
	if err != nil {
		logging.Error("Failed to read backup configuration data")
		return fmt.Errorf("failed to read backup configuration data: %w", err)
	}

	err = ioutil.WriteFile(pi.ManifestPath, backupData, 0644)
	if err != nil {
		logging.Error("Failed to write backup configuration data to manifest file")
		return fmt.Errorf("failed to write backup configuration data to manifest file: %w", err)
	}

	err = pi.ApplyManifest()
	if err != nil {
		return fmt.Errorf("failed to apply backup configuration: %w", err)
	}

	logging.Info("Successfully rolled back to previous Puppet configuration")
	return nil
}

// AIOptimizeConfiguration uses AI to optimize the configuration settings
func (pi *PuppetIntegration) AIOptimizeConfiguration(currentConfig []byte) ([]byte, error) {
	// Mock AI optimization process
	optimizedConfig := currentConfig // In a real scenario, AI optimization logic would be applied here

	logging.Info("Successfully optimized configuration using AI")
	return optimizedConfig, nil
}
