package storage

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"

    "github.com/ipfs/go-ipfs-api"
    "golang.org/x/crypto/scrypt"
)

// FileStorage manages file operations for blockchain data storage, ensuring security and efficiency.
type FileStorage struct {
    encryptionKey []byte
    ipfsShell     *shell.Shell
}

// NewFileStorage initializes a new FileStorage with a specified encryption key and IPFS connection.
func NewFileStorage(password string) (*FileStorage, error) {
    key, err := scrypt.Key([]byte(password), []byte("salt"), 16384, 8, 1, 32)
    if err != nil {
        return nil, err
    }

    return &FileStorage{
        encryptionKey: key,
        ipfsShell:     shell.NewShell("localhost:5001"),
    }, nil
}

// EncryptAndStoreFile encrypts and stores the file at the specified path.
func (fs *FileStorage) EncryptAndStoreFile(filePath string) (string, error) {
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return "", err
    }

    encryptedData, err := fs.encryptData(data)
    if err != nil {
        return "", err
    }

    cid, err := fs.ipfsShell.Add(bytes.NewReader(encryptedData))
    if err != nil {
        return "", err
    }

    return cid, nil
}

// RetrieveAndDecryptFile retrieves and decrypts the file identified by the cid.
func (fs *FileStorage) RetrieveAndDecryptFile(cid string) ([]byte, error) {
    reader, err := fs.ipfsShell.Cat(cid)
    if err != nil {
        return nil, err
    }
    encryptedData, err := ioutil.ReadAll(reader)
    if err != nil {
        return nil, err
    }

    return fs.decryptData(encryptedData)
}

// encryptData handles the encryption of data using AES.
func (fs *FileStorage) encryptData(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(fs.encryptionKey)
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

// decryptData handles the decryption of data using AES.
func (fs *FileStorage) decryptYou might also consider implementing more sophisticated error handling, logging, and security features to ensure the robustness and scalability of the file management system.Data(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(fs.encryptionKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, err
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// Cleanup is a utility function to remove temporary files securely.
func (fs *FileStorage) Cleanup(filePath string) error {
    return os.Remove(filePath)
}
