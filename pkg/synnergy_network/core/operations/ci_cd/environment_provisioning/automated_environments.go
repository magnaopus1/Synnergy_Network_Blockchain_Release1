package environment_provisioning

import (
    "fmt"
    "os/exec"
    "log"
    "context"
    "time"
    "github.com/synnergy_network/pkg/synnergy_network/utils"
    "github.com/synnergy_network/pkg/synnergy_network/security"
)

type Environment struct {
    Name       string
    Config     string
    Provisioned bool
}

type EnvironmentManager struct {
    Environments map[string]*Environment
}

// Initialize a new environment manager
func NewEnvironmentManager() *EnvironmentManager {
    return &EnvironmentManager{
        Environments: make(map[string]*Environment),
    }
}

// ProvisionEnvironment provisions a new environment based on the provided configuration
func (em *EnvironmentManager) ProvisionEnvironment(name, config string) error {
    if _, exists := em.Environments[name]; exists {
        return fmt.Errorf("environment %s already exists", name)
    }

    env := &Environment{
        Name:   name,
        Config: config,
    }

    err := em.runProvisioningScript(config)
    if err != nil {
        return fmt.Errorf("failed to provision environment: %v", err)
    }

    env.Provisioned = true
    em.Environments[name] = env

    return nil
}

// DeprovisionEnvironment deprovisions an existing environment
func (em *EnvironmentManager) DeprovisionEnvironment(name string) error {
    env, exists := em.Environments[name]
    if !exists {
        return fmt.Errorf("environment %s does not exist", name)
    }

    err := em.runDeprovisioningScript(env.Config)
    if err != nil {
        return fmt.Errorf("failed to deprovision environment: %v", err)
    }

    delete(em.Environments, name)
    return nil
}

// runProvisioningScript runs the provisioning script for an environment
func (em *EnvironmentManager) runProvisioningScript(config string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sh", "-c", config)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Provisioning script failed: %s", output)
        return err
    }

    log.Printf("Provisioning script output: %s", output)
    return nil
}

// runDeprovisioningScript runs the deprovisioning script for an environment
func (em *EnvironmentManager) runDeprovisioningScript(config string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sh", "-c", config)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Deprovisioning script failed: %s", output)
        return err
    }

    log.Printf("Deprovisioning script output: %s", output)
    return nil
}

// ListEnvironments lists all provisioned environments
func (em *EnvironmentManager) ListEnvironments() {
    for name, env := range em.Environments {
        fmt.Printf("Environment: %s, Provisioned: %t\n", name, env.Provisioned)
    }
}

// EncryptConfig encrypts the configuration for security purposes using AES
func (em *EnvironmentManager) EncryptConfig(config string) (string, error) {
    encryptedConfig, err := security.EncryptAES(config, utils.GenerateKey())
    if err != nil {
        return "", fmt.Errorf("failed to encrypt config: %v", err)
    }
    return encryptedConfig, nil
}

// DecryptConfig decrypts the configuration
func (em *EnvironmentManager) DecryptConfig(encryptedConfig string) (string, error) {
    decryptedConfig, err := security.DecryptAES(encryptedConfig, utils.GenerateKey())
    if err != nil {
        return "", fmt.Errorf("failed to decrypt config: %v", err)
    }
    return decryptedConfig, nil
}

func main() {
    em := NewEnvironmentManager()
    config := `echo "Provisioning environment"`

    // Encrypt the configuration
    encryptedConfig, err := em.EncryptConfig(config)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // Decrypt the configuration
    decryptedConfig, err := em.DecryptConfig(encryptedConfig)
    if err != nil {
        log.Fatalf("Decryption failed: %v", err)
    }

    // Provision an environment
    err = em.ProvisionEnvironment("dev", decryptedConfig)
    if err != nil {
        log.Fatalf("Provisioning failed: %v", err)
    }

    // List all environments
    em.ListEnvironments()

    // Deprovision an environment
    err = em.DeprovisionEnvironment("dev")
    if err != nil {
        log.Fatalf("Deprovisioning failed: %v", err)
    }

    // List all environments again
    em.ListEnvironments()
}
