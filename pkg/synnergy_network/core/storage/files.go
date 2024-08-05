package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/ipfs/go-ipfs-api"
	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/scrypt"
)

// File represents the structure for stored files
type File struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	Metadata  string    `json:"metadata"`
	Timestamp time.Time `json:"timestamp"`
}

// StorageService interface for file storage operations
type StorageService interface {
	SaveFile(name string, data []byte, metadata string) (string, error)
	GetFile(id string) ([]byte, error)
	DeleteFile(id string) error
	ListFiles() ([]File, error)
}

// LocalStorage implementation of StorageService using LevelDB and IPFS
type LocalStorage struct {
	db   *leveldb.DB
	ipfs *shell.Shell
	key  []byte
}

// NewLocalStorage creates a new instance of LocalStorage
func NewLocalStorage(dbPath string, ipfsURL string, encryptionKey string) (*LocalStorage, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	ipfs := shell.NewShell(ipfsURL)

	key, err := scrypt.Key([]byte(encryptionKey), []byte("salt"), 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &LocalStorage{
		db:   db,
		ipfs: ipfs,
		key:  key,
	}, nil
}

// SaveFile saves a file to local storage and IPFS
func (ls *LocalStorage) SaveFile(name string, data []byte, metadata string) (string, error) {
	// Encrypt data
	encryptedData, err := encrypt(data, ls.key)
	if err != nil {
		return "", err
	}

	// Upload to IPFS
	hash, err := ls.ipfs.Add(bytes.NewReader(encryptedData))
	if err != nil {
		return "", err
	}

	// Generate file ID
	id := uuid.New().String()

	// Create file record
	file := File{
		ID:        id,
		Name:      name,
		Hash:      hash,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	// Store file metadata in LevelDB
	fileData, err := json.Marshal(file)
	if err != nil {
		return "", err
	}
	err = ls.db.Put([]byte(id), fileData, nil)
	if err != nil {
		return "", err
	}

	return id, nil
}

// GetFile retrieves a file from local storage and IPFS
func (ls *LocalStorage) GetFile(id string) ([]byte, error) {
	// Retrieve file metadata from LevelDB
	fileData, err := ls.db.Get([]byte(id), nil)
	if err != nil {
		return nil, err
	}

	var file File
	err = json.Unmarshal(fileData, &file)
	if err != nil {
		return nil, err
	}

	// Retrieve data from IPFS
	reader, err := ls.ipfs.Cat(file.Hash)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, reader)
	if err != nil {
		return nil, err
	}

	// Decrypt data
	data, err := decrypt(buffer.Bytes(), ls.key)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// DeleteFile deletes a file from local storage
func (ls *LocalStorage) DeleteFile(id string) error {
	return ls.db.Delete([]byte(id), nil)
}

// ListFiles lists all files in local storage
func (ls *LocalStorage) ListFiles() ([]File, error) {
	var files []File
	iter := ls.db.NewIterator(nil, nil)
	for iter.Next() {
		var file File
		err := json.Unmarshal(iter.Value(), &file)
		if err != nil {
			continue
		}
		files = append(files, file)
	}
	iter.Release()
	return files, iter.Error()
}

// Encryption function using AES
func encrypt(data, key []byte) ([]byte, error) {
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

// Decryption function using AES
func decrypt(data, key []byte) ([]byte, error) {
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
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
