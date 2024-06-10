package interoperability

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"
)

// AssetWrapper handles the wrapping and unwrapping of assets across blockchains.
type AssetWrapper struct {
	db        storage.Database
	encryptor crypto.Encryptor
}

// NewAssetWrapper creates a new instance of AssetWrapper.
func NewAssetWrapper(db storage.Database, encryptor crypto.Encryptor) *AssetWrapper {
	return &AssetWrapper{
		db:        db,
		encryptor: encryptor,
	}
}

// WrapAsset tokenizes an asset for use on another blockchain.
func (aw *AssetWrapper) WrapAsset(assetID string, targetBlockchain string) (string, error) {
	asset, err := aw.db.Retrieve(assetID)
	if err != nil {
		return "", err
	}

	// Encrypt the asset data before sending it to another blockchain.
	encryptedAsset, err := aw.encryptData(asset)
	if err != nil {
		return "", err
	}

	// Here you would implement the logic to interact with another blockchain.
	// For example, sending the encrypted asset to the target blockchain.
	// This is a simulated response.
	wrappedTokenID := "simulatedTokenID-" + targetBlockchain

	return wrappedTokenID, nil
}

// UnwrapAsset converts the token back to the original asset on the original blockchain.
func (aw *AssetWrapper) UnwrapAsset(wrappedTokenID string) ([]byte, error) {
	// Simulate retrieving data from another blockchain.
	// Here, you would normally interact with the blockchain to get the encrypted asset.
	encryptedAsset := []byte("encryptedAssetData")

	// Decrypt the data to get the original asset.
	asset, err := aw.decryptData(encryptedAsset)
	if err != nil {
		return nil, err
	}

	return asset, nil
}

// encryptData uses AES encryption for data security.
func (aw *AssetWrapper) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aw.encryptor.Key())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptData decrypts data using AES.
func (aw *AssetWrapper) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(aw.encryptor.Key())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext size")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func main() {
	// Assuming db and encryptor are set up elsewhere and passed in.
	db := storage.NewDatabase()
	encryptor := crypto.NewAESGCMEncryptor([]byte("your-32-byte-secret-key"))
	wrapper := NewAssetWrapper(db, encryptor)

	// Example usage:
	wrappedID, err := wrapper.WrapAsset("asset123", "ethereum")
	if err != nil {
		panic(err)
	}
	println("Wrapped Asset ID:", wrappedID)

	asset, err := wrapper.UnwrapAsset(wrappedID)
	if err != nil {
		panic(err)
	}
	println("Unwrapped Asset Data:", string(asset))
}
