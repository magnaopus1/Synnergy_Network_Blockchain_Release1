package decentralized

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "io/ioutil"
    "net/http"

    "golang.org/x/crypto/scrypt"
)

// SwarmClient handles interactions with the Swarm network for decentralized file storage
type SwarmClient struct {
    BaseURL string
}

// NewSwarmClient initializes a new Swarm client
func NewSwarmClient(baseURL string) *SwarmClient {
    return &SwarmClient{
        BaseURL: baseURL,
    }
}

// UploadData encrypts and uploads data to Swarm, returning the Swarm hash
func (sc *SwarmClient) UploadData(data []byte, passphrase string) (string, error) {
    encryptedData, err := encryptData(data, passphrase)
    if err != nil {
        return "", err
    }

    return sc.uploadToSwarm(encryptedData)
}

// RetrieveData downloads and decrypts data from Swarm using the given hash and passphrase
func (sc *SwarmClient) RetrieveData(swarmHash string, passphrase string) ([]byte, error) {
    data, err := sc.downloadFromSwarm(swarmHash)
    if err != nil {
        return nil, err
    }

    return decryptData(data, passphrase)
}

// encryptData uses AES-256-GCM for encryption, utilizing Scrypt for key derivation
func encryptData(data []byte, passphrase string) ([]byte, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return nil, err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
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

    nonce := make([]byte, gcm.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return append(salt, ciphertext...), nil
}

// decryptData decrypts data using AES-256-GCM and Scrypt-derived keys
func decryptData(data []byte, passphrase string) ([]byte, error) {
    if len(data) < 48 {
        return nil, errors.New("encrypted data too short")
    }

    salt, ciphertext := data[:16], data[16:]
    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
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

    nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// uploadToSwarm handles the actual HTTP POST request to the Swarm network
func (sc *SwarmClient) uploadToSwarm(data []byte) (string, error) {
    resp, err := http.Post(sc.BaseURL+"/bzz:/", "application/octet-stream", bytes.NewReader(data))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", errors.New("failed to upload data to Swarm")
    }

    hash, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    return string(hash), nil
}

// downloadFromSwarm handles the HTTP GET request to retrieve data from the Swarm network
func (sc *SwarmClient) downloadFromSwarm(swarmHash string) ([]byte, error) {
    resp, err := http.Get(sc.BaseURL + "/bzz:/" + swarmHash + "/")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, errors.New("failed to retrieve data from Swarm")
    }

    return ioutil.ReadAll(resp.Body)
}

func main() {
    // Example of creating a Swarm client and using it to upload and retrieve data
    client := NewSwarmClient("http://localhost:8500")
    data := []byte("Hello, blockchain world!")
    passphrase := "securePassphrase123"

    // Upload data
    hash, err := client.UploadData(data, passphrase)
    if err != nil {
        fmt.Println("Upload failed:", err)
        return
    }

    fmt.Println("Uploaded to Swarm with hash:", hash)

    // Retrieve data
    retrievedData, err := client.RetrieveData(hash, passphrase)
    if err != nil {
        fmt.Println("Retrieval failed:", err)
        return
    }

    fmt.Println("Retrieved data:", string(retrievedData))
}
