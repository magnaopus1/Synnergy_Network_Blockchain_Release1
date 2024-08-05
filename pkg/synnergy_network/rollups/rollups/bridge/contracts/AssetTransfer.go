package contracts

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// Asset represents a transferable asset
type Asset struct {
    ID            string
    Owner         string
    Value         float64
    TransferHash  string
    CreatedAt     time.Time
    UpdatedAt     time.Time
    EncryptedData string
}

// TransferRequest represents a request to transfer an asset
type TransferRequest struct {
    AssetID       string
    FromOwner     string
    ToOwner       string
    TransferValue float64
    Timestamp     time.Time
    Signature     string
}

// AssetTransferContract represents the contract for asset transfers
type AssetTransferContract struct {
    Assets map[string]Asset
}

// NewAssetTransferContract initializes a new AssetTransferContract
func NewAssetTransferContract() *AssetTransferContract {
    return &AssetTransferContract{
        Assets: make(map[string]Asset),
    }
}

// CreateAsset creates a new asset with encryption
func (atc *AssetTransferContract) CreateAsset(owner string, value float64, secret string) (string, error) {
    id := uuid.New().String()
    encryptedData, err := encryptData(secret, fmt.Sprintf("%s:%f", owner, value))
    if err != nil {
        return "", err
    }
    asset := Asset{
        ID:            id,
        Owner:         owner,
        Value:         value,
        TransferHash:  "",
        CreatedAt:     time.Now(),
        UpdatedAt:     time.Now(),
        EncryptedData: encryptedData,
    }
    atc.Assets[id] = asset
    return id, nil
}

// TransferAsset transfers an asset from one owner to another
func (atc *AssetTransferContract) TransferAsset(request TransferRequest, secret string) error {
    asset, exists := atc.Assets[request.AssetID]
    if !exists {
        return errors.New("asset does not exist")
    }
    if asset.Owner != request.FromOwner {
        return errors.New("transfer request is not from the current owner")
    }
    if asset.Value < request.TransferValue {
        return errors.New("insufficient asset value for transfer")
    }

    transferHash := generateTransferHash(request, secret)
    if transferHash != request.Signature {
        return errors.New("invalid transfer signature")
    }

    asset.Value -= request.TransferValue
    asset.UpdatedAt = time.Now()
    atc.Assets[request.AssetID] = asset

    newAssetID := uuid.New().String()
    newAsset := Asset{
        ID:            newAssetID,
        Owner:         request.ToOwner,
        Value:         request.TransferValue,
        TransferHash:  transferHash,
        CreatedAt:     time.Now(),
        UpdatedAt:     time.Now(),
        EncryptedData: asset.EncryptedData,
    }
    atc.Assets[newAssetID] = newAsset

    return nil
}

// EncryptData encrypts the given data using AES
func encryptData(secret, data string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts the given data using AES
func decryptData(secret, encryptedData string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(decrypted), nil
}

// CreateHash creates a hash from the secret key
func createHash(key string) string {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateTransferHash generates a hash for the transfer request
func generateTransferHash(request TransferRequest, secret string) string {
    data := fmt.Sprintf("%s:%s:%s:%f:%s", request.AssetID, request.FromOwner, request.ToOwner, request.TransferValue, request.Timestamp.String())
    return createHash(data + secret)
}

// GenerateSignature generates a signature for the transfer request using Argon2
func generateSignature(request TransferRequest, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(fmt.Sprintf("%s:%s:%s:%f:%s", request.AssetID, request.FromOwner, request.ToOwner, request.TransferValue, request.Timestamp.String())), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}

