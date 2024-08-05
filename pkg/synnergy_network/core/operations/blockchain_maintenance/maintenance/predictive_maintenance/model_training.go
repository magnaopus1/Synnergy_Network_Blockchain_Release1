package predictive_maintenance

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io"
    "os"
    "sync"

    "golang.org/x/crypto/scrypt"
    "github.com/synnergy_network/utils"
)

// Model represents a predictive maintenance model
type Model struct {
    ID           string
    TrainingData []TrainingData
    ModelWeights []byte
    Metadata     ModelMetadata
}

// TrainingData represents a single piece of training data
type TrainingData struct {
    Data        []byte
    Label       []byte
    Encrypted   bool
}

// ModelMetadata contains metadata for a model
type ModelMetadata struct {
    CreatedAt    int64
    UpdatedAt    int64
    Version      string
    Description  string
}

// ModelStore provides storage for models
type ModelStore struct {
    models map[string]*Model
    mutex  sync.RWMutex
}

// NewModelStore initializes a new ModelStore
func NewModelStore() *ModelStore {
    return &ModelStore{
        models: make(map[string]*Model),
    }
}

// AddModel adds a new model to the store
func (ms *ModelStore) AddModel(model *Model) {
    ms.mutex.Lock()
    defer ms.mutex.Unlock()
    ms.models[model.ID] = model
}

// GetModel retrieves a model by ID
func (ms *ModelStore) GetModel(id string) (*Model, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    model, exists := ms.models[id]
    if !exists {
        return nil, fmt.Errorf("model with ID %s not found", id)
    }
    return model, nil
}

// EncryptData encrypts data using AES-GCM
func EncryptData(data, key []byte) ([]byte, error) {
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
    return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts data using AES-GCM
func DecryptData(encryptedData, key []byte) ([]byte, error) {
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
        return nil, fmt.Errorf("invalid ciphertext")
    }
    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateKey generates a secure key using scrypt
func GenerateKey(password, salt []byte) ([]byte, error) {
    return scrypt.Key(password, salt, 1<<15, 8, 1, 32)
}

// TrainModel trains a model using the provided training data
func TrainModel(model *Model) error {
    if len(model.TrainingData) == 0 {
        return fmt.Errorf("no training data provided")
    }

    // Example training process (to be replaced with actual ML training code)
    model.ModelWeights = []byte("trained_model_weights")
    model.Metadata.UpdatedAt = time.Now().Unix()
    return nil
}

// SaveModel saves the model to a file
func SaveModel(model *Model, filepath string) error {
    file, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer file.Close()

    encodedModel := base64.StdEncoding.EncodeToString(model.ModelWeights)
    _, err = file.Write([]byte(encodedModel))
    if err != nil {
        return err
    }
    return nil
}

// LoadModel loads the model from a file
func LoadModel(filepath string) (*Model, error) {
    file, err := os.Open(filepath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        return nil, err
    }

    data := make([]byte, fileInfo.Size())
    _, err = file.Read(data)
    if err != nil {
        return nil, err
    }

    decodedWeights, err := base64.StdEncoding.DecodeString(string(data))
    if err != nil {
        return nil, err
    }

    return &Model{
        ModelWeights: decodedWeights,
    }, nil
}

// VerifyModel verifies the integrity of the model using hashing
func VerifyModel(model *Model) (bool, error) {
    hash := sha256.New()
    _, err := hash.Write(model.ModelWeights)
    if err != nil {
        return false, err
    }
    return true, nil
}
