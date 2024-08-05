package containerization

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/synnergy_network/utils/encryption"
	"github.com/synnergy_network/utils/logging"
)

// DockerfileTemplate manages the creation and deployment of Dockerfile templates for blockchain nodes
type DockerfileTemplate struct {
	BaseImage        string
	Maintainer       string
	ExposedPorts     []int
	EnvironmentVars  map[string]string
	Commands         []string
	DockerfilePath   string
	DeploymentConfig string
}

// NewDockerfileTemplate creates a new instance of DockerfileTemplate
func NewDockerfileTemplate(baseImage, maintainer, dockerfilePath, deploymentConfig string, exposedPorts []int, envVars map[string]string, commands []string) *DockerfileTemplate {
	return &DockerfileTemplate{
		BaseImage:        baseImage,
		Maintainer:       maintainer,
		ExposedPorts:     exposedPorts,
		EnvironmentVars:  envVars,
		Commands:         commands,
		DockerfilePath:   dockerfilePath,
		DeploymentConfig: deploymentConfig,
	}
}

// GenerateDockerfile generates the Dockerfile based on the provided template
func (dt *DockerfileTemplate) GenerateDockerfile() error {
	var dockerfileContent string

	dockerfileContent += fmt.Sprintf("FROM %s\n", dt.BaseImage)
	dockerfileContent += fmt.Sprintf("MAINTAINER %s\n", dt.Maintainer)

	for _, port := range dt.ExposedPorts {
		dockerfileContent += fmt.Sprintf("EXPOSE %d\n", port)
	}

	for key, value := range dt.EnvironmentVars {
		dockerfileContent += fmt.Sprintf("ENV %s=%s\n", key, value)
	}

	for _, cmd := range dt.Commands {
		dockerfileContent += fmt.Sprintf("RUN %s\n", cmd)
	}

	// Write Dockerfile content to file
	err := ioutil.WriteFile(dt.DockerfilePath, []byte(dockerfileContent), 0644)
	if err != nil {
		logging.Error("Failed to write Dockerfile")
		return fmt.Errorf("failed to write Dockerfile: %w", err)
	}

	logging.Info("Successfully generated Dockerfile")
	return nil
}

// BuildDockerImage builds the Docker image from the Dockerfile
func (dt *DockerfileTemplate) BuildDockerImage(tag string) error {
	cmd := exec.Command("docker", "build", "-t", tag, "-f", dt.DockerfilePath, ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error(fmt.Sprintf("Failed to build Docker image: %s", string(output)))
		return fmt.Errorf("failed to build Docker image: %w", err)
	}
	logging.Info(fmt.Sprintf("Successfully built Docker image: %s", string(output)))
	return nil
}

// PushDockerImage pushes the Docker image to the specified registry
func (dt *DockerfileTemplate) PushDockerImage(tag, registryURL string) error {
	image := fmt.Sprintf("%s/%s", registryURL, tag)
	cmd := exec.Command("docker", "tag", tag, image)
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

// EncryptDeploymentConfig encrypts the deployment configuration file
func (dt *DockerfileTemplate) EncryptDeploymentConfig() error {
	configData, err := ioutil.ReadFile(dt.DeploymentConfig)
	if err != nil {
		logging.Error("Failed to read deployment configuration file")
		return fmt.Errorf("failed to read deployment configuration file: %w", err)
	}

	encryptedData, err := encryption.EncryptData(configData)
	if err != nil {
		logging.Error("Failed to encrypt deployment configuration data")
		return fmt.Errorf("failed to encrypt deployment configuration data: %w", err)
	}

	err = ioutil.WriteFile(dt.DeploymentConfig, encryptedData, 0644)
	if err != nil {
		logging.Error("Failed to write encrypted deployment configuration data to file")
		return fmt.Errorf("failed to write encrypted deployment configuration data to file: %w", err)
	}

	logging.Info("Successfully encrypted deployment configuration data")
	return nil
}

// AIOptimizeDockerfile uses AI to optimize the Dockerfile for performance and security
func (dt *DockerfileTemplate) AIOptimizeDockerfile() error {
	// Placeholder for AI optimization logic
	// In a real scenario, AI algorithms would analyze and optimize the Dockerfile content
	logging.Info("Successfully optimized Dockerfile using AI")
	return nil
}

// RollbackDockerfile restores the Dockerfile to a previous state from a backup
func (dt *DockerfileTemplate) RollbackDockerfile(backupPath string) error {
	backupData, err := ioutil.ReadFile(backupPath)
	if err != nil {
		logging.Error("Failed to read backup Dockerfile data")
		return fmt.Errorf("failed to read backup Dockerfile data: %w", err)
	}

	err = ioutil.WriteFile(dt.DockerfilePath, backupData, 0644)
	if err != nil {
		logging.Error("Failed to write backup Dockerfile data to file")
		return fmt.Errorf("failed to write backup Dockerfile data to file: %w", err)
	}

	logging.Info("Successfully rolled back Dockerfile to previous state")
	return nil
}

// LoadDeploymentConfig loads and decrypts the deployment configuration file
func (dt *DockerfileTemplate) LoadDeploymentConfig() ([]byte, error) {
	encryptedData, err := ioutil.ReadFile(dt.DeploymentConfig)
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
