package smart_contract_deployment

import (
    "fmt"
    "log"
    "os/exec"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "golang.org/x/crypto/scrypt"
)

// DeploymentScript represents a smart contract deployment script
type DeploymentScript struct {
    ScriptName string
    ScriptPath string
    ContractAddress string
    Encrypted bool
}

// CompileContract compiles the smart contract from source
func (ds *DeploymentScript) CompileContract(sourcePath string) error {
    cmd := exec.Command("solc", "--bin", "--abi", "-o", ds.ScriptPath, sourcePath)
    out, err := cmd.CombinedOutput()
    if err != nil {
        log.Fatalf("Compilation failed: %s", err)
        return err
    }
    fmt.Printf("Compilation output: %s\n", string(out))
    return nil
}

// DeployContract deploys the compiled smart contract to the blockchain
func (ds *DeploymentScript) DeployContract(abiPath string, binPath string, network string, privateKey string) error {
    // Command to deploy the contract
    cmd := exec.Command("web3", "deploy", "--abi", abiPath, "--bin", binPath, "--network", network, "--private-key", privateKey)
    out, err := cmd.CombinedOutput()
    if err != nil {
        log.Fatalf("Deployment failed: %s", err)
        return err
    }
    fmt.Printf("Deployment output: %s\n", string(out))
    // Extract contract address from output
    // This is a placeholder and should be adjusted based on actual command output
    ds.ContractAddress = extractContractAddress(out)
    return nil
}

// EncryptScript encrypts the deployment script using AES
func (ds *DeploymentScript) EncryptScript(password string) error {
    if ds.Encrypted {
        return fmt.Errorf("Script already encrypted")
    }

    key, salt, err := generateKey(password)
    if err != nil {
        return err
    }

    plaintext, err := os.ReadFile(ds.ScriptPath)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    encryptedFilePath := ds.ScriptPath + ".enc"
    err = os.WriteFile(encryptedFilePath, append(salt, ciphertext...), 0644)
    if err != nil {
        return err
    }

    ds.ScriptPath = encryptedFilePath
    ds.Encrypted = true
    return nil
}

// DecryptScript decrypts the encrypted deployment script
func (ds *DeploymentScript) DecryptScript(password string) error {
    if !ds.Encrypted {
        return fmt.Errorf("Script not encrypted")
    }

    encryptedContent, err := os.ReadFile(ds.ScriptPath)
    if err != nil {
        return err
    }

    salt := encryptedContent[:32]
    ciphertext := encryptedContent[32:]

    key, _, err := generateKeyWithSalt(password, salt)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return fmt.Errorf("Ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    decryptedFilePath := ds.ScriptPath[:len(ds.ScriptPath)-4]
    err = os.WriteFile(decryptedFilePath, plaintext, 0644)
    if err != nil {
        return err
    }

    ds.ScriptPath = decryptedFilePath
    ds.Encrypted = false
    return nil
}

// extractContractAddress extracts the contract address from deployment output
func extractContractAddress(output []byte) string {
    // Placeholder function to extract contract address from output
    // Actual implementation may vary based on the specific output format
    return "0x1234567890abcdef1234567890abcdef12345678"
}

// generateKey generates a key and salt for encryption
func generateKey(password string) ([]byte, []byte, error) {
    salt := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, nil, err
    }

    key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
    if err != nil {
        return nil, nil, err
    }
    return key, salt, nil
}

// generateKeyWithSalt generates a key using a given salt for decryption
func generateKeyWithSalt(password string, salt []byte) ([]byte, []byte, error) {
    key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
    if err != nil {
        return nil, nil, err
    }
    return key, salt, nil
}
