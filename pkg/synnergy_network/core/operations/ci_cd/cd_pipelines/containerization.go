package cd_pipelines

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"time"
	"github.com/synnergy_network/blockchain/core"
	"github.com/synnergy_network/blockchain/security"
	"github.com/synnergy_network/blockchain/monitoring"
)

// DeploymentConfig holds the configuration for container deployment
type DeploymentConfig struct {
	Image            string
	ContainerName    string
	Namespace        string
	Replicas         int
	Port             int
	KubeConfigPath   string
	EnvironmentVars  map[string]string
	Monitoring       bool
	RolloutStrategy  string
}

// DeployContainer handles the deployment of a containerized application
func DeployContainer(config DeploymentConfig) error {
	err := buildDockerImage(config.Image)
	if err != nil {
		return fmt.Errorf("failed to build Docker image: %v", err)
	}

	err = pushDockerImage(config.Image)
	if err != nil {
		return fmt.Errorf("failed to push Docker image: %v", err)
	}

	err = createKubernetesDeployment(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes deployment: %v", err)
	}

	if config.Monitoring {
		err = setupMonitoring(config)
		if err != nil {
			return fmt.Errorf("failed to setup monitoring: %v", err)
		}
	}

	log.Println("Container deployment completed successfully.")
	return nil
}

// buildDockerImage builds the Docker image
func buildDockerImage(image string) error {
	cmd := exec.Command("docker", "build", "-t", image, ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Docker build failed: %v, %s", err, output)
	}
	return nil
}

// pushDockerImage pushes the Docker image to a registry
func pushDockerImage(image string) error {
	cmd := exec.Command("docker", "push", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Docker push failed: %v, %s", err, output)
	}
	return nil
}

// createKubernetesDeployment creates a Kubernetes deployment
func createKubernetesDeployment(config DeploymentConfig) error {
	deploymentYAML := generateDeploymentYAML(config)
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(deploymentYAML)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %v, %s", err, output)
	}
	return nil
}

// generateDeploymentYAML generates Kubernetes deployment YAML
func generateDeploymentYAML(config DeploymentConfig) string {
	envVars := ""
	for key, value := range config.EnvironmentVars {
		envVars += fmt.Sprintf("- name: %s\n  value: \"%s\"\n", key, value)
	}

	deploymentYAML := fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
spec:
  replicas: %d
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
      - name: %s
        image: %s
        ports:
        - containerPort: %d
        env:
%s
`, config.ContainerName, config.Namespace, config.Replicas, config.ContainerName, config.ContainerName, config.ContainerName, config.Image, config.Port, envVars)

	return deploymentYAML
}

// setupMonitoring sets up monitoring for the deployment
func setupMonitoring(config DeploymentConfig) error {
	monitoringConfig := monitoring.Config{
		Namespace: config.Namespace,
		Service:   config.ContainerName,
	}

	err := monitoring.Setup(monitoringConfig)
	if err != nil {
		return fmt.Errorf("monitoring setup failed: %v", err)
	}
	return nil
}

// EncryptData securely encrypts data before deployment
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt, err := generateRandomBytes(16)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := generateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData securely decrypts data after retrieval
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generateRandomBytes generates random bytes for encryption
func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	return bytes, err
}
