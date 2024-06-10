package decentralized

import (
    "bytes"
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "io"
    "io/ioutil"

    "github.com/ipfs/go-ipfs-api"
    "golang.org/x/crypto/argon2"
)

// IPFSClient wraps the Shell struct to interact with IPFS
type IPFSClient struct {
    shell *shell.Shell
}

// NewIPFSClient creates a new IPFS client
func NewIPFSClient(ipfsAddress string) *IPFSClient {
    return &IPFSClient{
        shell: shell.NewShell(ipfsAddress),
    }
}

// AddData adds data to IPFS with encryption and returns the hash of the added data
func (client *IPFSClient) AddData(data []byte, passphrase string) (string, error) {
    // Encrypt data before storing it to IPFS
    encryptedData, err := encryptData(data, passphrase)
    if err != nil {
        return "", fmt.Errorf("failed to encrypt data: %w", err)
    }

    hash, err := client.shell.Add(bytes.NewReader(encryptedData))
    if err != nil {
        return "", fmt.Errorf("failed to add data to IPFS: %w", err)
    }
    return hash, nil
}

// GetData retrieves and decrypts data from IPFS based on the given hash
func (client *IPFSClient) GetData(hash string, passphrase string) ([]byte, error) {
    reader, err := client.shell.Cat(hash)
    if err != nil {
        return nil, fmt.Errorf("failed to retrieve data from IPFS: %w", err)
    }
    defer reader.Close()

    encryptedData, err := ioutil.ReadAll(reader)
    if err != nil {
    return nil, fmt.Errorf("failed to read data from IPFS: %w", err)
    }

    // Decrypt data after retrieving it
    data, err := decryptData(encryptedData, passphrase)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt data: %w", err)
    }

    return data, nil
}

// encryptData encrypts data using AES-GCM with Argon2 for key derivation
func encryptData(data []byte, passphrase string) ([]byte, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }

    key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
    return nil, err
    }

    encryptedData := gcm.Seal(nonce, nonce, data, nil)
    return encryptedData, nil
}

// decryptData decrypts data using AES-GCM with Argon2 for key derivation
func decryptData(encryptedData []byte, passphrase string) ([]byte, error) {
    salt := encryptedData[:16]
    key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    data, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
    return data, nil
}

func main() {
    // Example usage with address of the IPFS daemon and passphrase for encryption
    ipfsClient := NewIPFSClient("localhost:5001")
    data := []byte("Hello, encrypted world of IPFS and blockchain!")
    passphrase := "strongpassword123"

    hash, err := ipfsClient.AddData(data, passphrase)
    if err != nil {
        fmt.Println("Error storing data:", err)
        return
    }

    retrievedData, err := ipfsClient.GetData(hash, passphrase)
    if err != nil {
        fmt.Println("Error retrieving data:", err)
        return
    }

    fmt.Println("Retrieved data:", string(retrievedData))
}
