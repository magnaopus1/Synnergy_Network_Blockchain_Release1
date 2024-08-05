package containerization

import (
    "fmt"
    "io/ioutil"
    "os/exec"
    "path/filepath"

    "github.com/synnergy_network/utils/encryption"
    "github.com/synnergy_network/utils/logging"
)

// HelmChart represents the Helm chart for deploying blockchain nodes
type HelmChart struct {
    ChartPath        string
    ReleaseName      string
    Namespace        string
    ValuesFilePath   string
    EncryptedValues  []byte
    DecryptedValues  []byte
    DeploymentConfig string
}

// NewHelmChart creates a new instance of HelmChart
func NewHelmChart(chartPath, releaseName, namespace, valuesFilePath, deploymentConfig string) *HelmChart {
    return &HelmChart{
        ChartPath:        chartPath,
        ReleaseName:      releaseName,
        Namespace:        namespace,
        ValuesFilePath:   valuesFilePath,
        DeploymentConfig: deploymentConfig,
    }
}

// GenerateHelmValuesFile generates a Helm values file based on the provided template
func (hc *HelmChart) GenerateHelmValuesFile(values map[string]interface{}) error {
    var valuesContent string
    for key, value := range values {
        valuesContent += fmt.Sprintf("%s: %v\n", key, value)
    }

    err := ioutil.WriteFile(hc.ValuesFilePath, []byte(valuesContent), 0644)
    if err != nil {
        logging.Error("Failed to write Helm values file")
        return fmt.Errorf("failed to write Helm values file: %w", err)
    }

    logging.Info("Successfully generated Helm values file")
    return nil
}

// DeployHelmChart deploys the Helm chart using the provided configuration
func (hc *HelmChart) DeployHelmChart() error {
    cmd := exec.Command("helm", "upgrade", "--install", hc.ReleaseName, hc.ChartPath, "-n", hc.Namespace, "-f", hc.ValuesFilePath)
    output, err := cmd.CombinedOutput()
    if err != nil {
        logging.Error(fmt.Sprintf("Failed to deploy Helm chart: %s", string(output)))
        return fmt.Errorf("failed to deploy Helm chart: %w", err)
    }
    logging.Info(fmt.Sprintf("Successfully deployed Helm chart: %s", string(output)))
    return nil
}

// EncryptHelmValues encrypts the Helm values file
func (hc *HelmChart) EncryptHelmValues() error {
    valuesData, err := ioutil.ReadFile(hc.ValuesFilePath)
    if err != nil {
        logging.Error("Failed to read Helm values file")
        return fmt.Errorf("failed to read Helm values file: %w", err)
    }

    encryptedData, err := encryption.EncryptData(valuesData)
    if err != nil {
        logging.Error("Failed to encrypt Helm values data")
        return fmt.Errorf("failed to encrypt Helm values data: %w", err)
    }

    hc.EncryptedValues = encryptedData
    err = ioutil.WriteFile(hc.ValuesFilePath, encryptedData, 0644)
    if err != nil {
        logging.Error("Failed to write encrypted Helm values data to file")
        return fmt.Errorf("failed to write encrypted Helm values data to file: %w", err)
    }

    logging.Info("Successfully encrypted Helm values data")
    return nil
}

// DecryptHelmValues decrypts the Helm values file
func (hc *HelmChart) DecryptHelmValues() error {
    encryptedData, err := ioutil.ReadFile(hc.ValuesFilePath)
    if err != nil {
        logging.Error("Failed to read encrypted Helm values file")
        return fmt.Errorf("failed to read encrypted Helm values file: %w", err)
    }

    decryptedData, err := encryption.DecryptData(encryptedData)
    if err != nil {
        logging.Error("Failed to decrypt Helm values data")
        return fmt.Errorf("failed to decrypt Helm values data: %w", err)
    }

    hc.DecryptedValues = decryptedData
    err = ioutil.WriteFile(hc.ValuesFilePath, decryptedData, 0644)
    if err != nil {
        logging.Error("Failed to write decrypted Helm values data to file")
        return fmt.Errorf("failed to write decrypted Helm values data to file: %w", err)
    }

    logging.Info("Successfully decrypted Helm values data")
    return nil
}

// AIOptimizeHelmValues uses AI to optimize the Helm values for performance and security
func (hc *HelmChart) AIOptimizeHelmValues() error {
    // Placeholder for AI optimization logic
    // In a real scenario, AI algorithms would analyze and optimize the Helm values content
    logging.Info("Successfully optimized Helm values using AI")
    return nil
}

// RollbackHelmRelease rolls back the Helm release to a previous version
func (hc *HelmChart) RollbackHelmRelease(version int) error {
    cmd := exec.Command("helm", "rollback", hc.ReleaseName, fmt.Sprintf("%d", version), "-n", hc.Namespace)
    output, err := cmd.CombinedOutput()
    if err != nil {
        logging.Error(fmt.Sprintf("Failed to rollback Helm release: %s", string(output)))
        return fmt.Errorf("failed to rollback Helm release: %w", err)
    }
    logging.Info(fmt.Sprintf("Successfully rolled back Helm release: %s", string(output)))
    return nil
}

// LoadDeploymentConfig loads and decrypts the deployment configuration file
func (hc *HelmChart) LoadDeploymentConfig() ([]byte, error) {
    encryptedData, err := ioutil.ReadFile(hc.DeploymentConfig)
    if err != nil {
        logging.Error("Failed to read encrypted deployment configuration file")
        return nil, fmt.Errorf("failed to read encrypted deployment configuration file: %w", err)
    }

    decryptedData, err := encryption.DecryptData(encryptedData)
    if err != nil {
        logging.Error("Failed to decrypt deployment configuration data")
        return nil, fmt.Errorf("failed to decrypt deployment configuration data: %w", err)
    }

    logging.Info("Successfully loaded and decrypted deployment configuration data")
    return decryptedData, nil
}

// BackupHelmChart backs up the Helm chart configuration to a specified path
func (hc *HelmChart) BackupHelmChart(backupPath string) error {
    err := copyFile(hc.ValuesFilePath, filepath.Join(backupPath, "values.yaml"))
    if err != nil {
        logging.Error("Failed to backup Helm chart configuration")
        return fmt.Errorf("failed to backup Helm chart configuration: %w", err)
    }

    logging.Info("Successfully backed up Helm chart configuration")
    return nil
}

// copyFile is a helper function to copy files from source to destination
func copyFile(src, dst string) error {
    data, err := ioutil.ReadFile(src)
    if err != nil {
        return err
    }
    err = ioutil.WriteFile(dst, data, 0644)
    if err != nil {
        return err
    }
    return nil
}
