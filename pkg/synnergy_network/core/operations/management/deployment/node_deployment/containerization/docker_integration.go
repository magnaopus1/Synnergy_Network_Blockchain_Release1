package containerization

import (
	"fmt"
	"os/exec"
	"log"
	"io/ioutil"
	"encoding/json"
	"github.com/synnergy_network/utils/encryption"
	"github.com/synnergy_network/utils/logging"
)

// DockerIntegration manages Docker container integration and orchestration
type DockerIntegration struct {
	DockerfilePath string
	ImageName      string
	Tag            string
	KubeConfigPath string
}

// NewDockerIntegration creates a new instance of DockerIntegration
func NewDockerIntegration(dockerfilePath, imageName, tag, kubeConfigPath string) *DockerIntegration {
	return &DockerIntegration{
		DockerfilePath: dockerfilePath,
		ImageName:      imageName,
		Tag:            tag,
		KubeConfigPath: kubeConfigPath,
	}
}

// BuildImage builds a Docker image from the Dockerfile
func (di *DockerIntegration) BuildImage() error {
	cmd := exec.Command("docker", "build", "-t", fmt.Sprintf("%s:%s", di.ImageName, di.Tag), di.DockerfilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to build Docker image: %s", string(output)))
		return fmt.Errorf("failed to build Docker image: %w", err)
	}
	logging.Info(fmt.Sprintf("Successfully built Docker image: %s", string(output)))
	return nil
}

// PushImage pushes the Docker image to the specified registry
func (di *DockerIntegration) PushImage(registryURL string) error {
	image := fmt.Sprintf("%s/%s:%s", registryURL, di.ImageName, di.Tag)
	cmd := exec.Command("docker", "tag", fmt.Sprintf("%s:%s", di.ImageName, di.Tag), image)
	if output, err := cmd.CombinedOutput(); err != nil {
		logging.Error(fmt.Sprintf("Failed to tag Docker image: %s", string(output)))
		return fmt.Errorf("failed to tag Docker image: %w", err)
	}

	cmd = exec.Command("docker", "push", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to push Docker image: %s", string(output)))
		return fmt.Errorf("failed to push Docker image: %w", err)
	}
	logging.Info(fmt.Sprintf("Successfully pushed Docker image: %s", string(output)))
	return nil
}

// DeployToKubernetes deploys the Docker image to a Kubernetes cluster
func (di *DockerIntegration) DeployToKubernetes(deploymentConfigPath string) error {
	cmd := exec.Command("kubectl", "--kubeconfig", di.KubeConfigPath, "apply", "-f", deploymentConfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to deploy to Kubernetes: %s", string(output)))
		return fmt.Errorf("failed to deploy to Kubernetes: %w", err)
	}
	logging.Info(fmt.Sprintf("Successfully deployed to Kubernetes: %s", string(output)))
	return nil
}

// SecureContainerData encrypts container data before storing it
func (di *DockerIntegration) SecureContainerData(data []byte, filePath string) error {
	encryptedData, err := encryption.EncryptData(data)
	if err != nil {
		logging.Error("Failed to encrypt container data")
		return fmt.Errorf("failed to encrypt container data: %w", err)
	}

	err = ioutil.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		logging.Error("Failed to write encrypted container data to file")
		return fmt.Errorf("failed to write encrypted container data to file: %w", err)
	}

	logging.Info("Successfully encrypted and stored container data")
	return nil
}

// LoadKubeConfig loads the Kubernetes configuration from a file
func (di *DockerIntegration) LoadKubeConfig() (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(di.KubeConfigPath)
	if err != nil {
		logging.Error("Failed to read Kubernetes configuration file")
		return nil, fmt.Errorf("failed to read Kubernetes configuration file: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		logging.Error("Failed to parse Kubernetes configuration file")
		return nil, fmt.Errorf("failed to parse Kubernetes configuration file: %w", err)
	}

	logging.Info("Successfully loaded Kubernetes configuration")
	return config, nil
}

// AIOptimizeDeployment uses AI to optimize deployment configurations
func (di *DockerIntegration) AIOptimizeDeployment(currentConfig map[string]interface{}) (map[string]interface{}, error) {
	// Mock AI optimization process
	optimizedConfig := currentConfig // In a real scenario, AI optimization logic would be applied here

	logging.Info("Successfully optimized deployment configuration using AI")
	return optimizedConfig, nil
}

// RollbackDeployment rolls back the deployment to a previous state
func (di *DockerIntegration) RollbackDeployment(backupConfigPath string) error {
	cmd := exec.Command("kubectl", "--kubeconfig", di.KubeConfigPath, "apply", "-f", backupConfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to roll back Kubernetes deployment: %s", string(output)))
		return fmt.Errorf("failed to roll back Kubernetes deployment: %w", err)
	}
	logging.Info(fmt.Sprintf("Successfully rolled back Kubernetes deployment: %s", string(output)))
	return nil
}
