package compression

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// StorageFormats provides functionalities for managing different storage formats with compression and encryption.
type StorageFormats struct {
	key []byte
}

// NewStorageFormats initializes the StorageFormats with a passphrase.
func NewStorageFormats(passphrase string) (*StorageFormats, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &StorageFormats{
		key: key,
	}, nil
}

// SaveAsJSON compresses, encrypts, and saves the data in JSON format.
func (sf *StorageFormats) SaveAsJSON(filename string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return sf.saveToFile(filename, jsonData)
}

// LoadFromJSON loads, decrypts, and decompresses the data from a JSON file.
func (sf *StorageFormats) LoadFromJSON(filename string, result interface{}) error {
	data, err := sf.loadFromFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, result)
}

// SaveAsBinary compresses, encrypts, and saves the data in binary format.
func (sf *StorageFormats) SaveAsBinary(filename string, data []byte) error {
	return sf.saveToFile(filename, data)
}

// LoadFromBinary loads, decrypts, and decompresses the data from a binary file.
func (sf *StorageFormats) LoadFromBinary(filename string) ([]byte, error) {
	return sf.loadFromFile(filename)
}

// SaveAsGZIP compresses and saves the data in GZIP format.
func (sf *StorageFormats) SaveAsGZIP(filename string, data []byte) error {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return ioutil.WriteFile(filename, b.Bytes(), 0644)
}

// LoadFromGZIP loads and decompresses the data from a GZIP file.
func (sf *StorageFormats) LoadFromGZIP(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ioutil.ReadAll(r)
}

// SaveAsZLIB compresses and saves the data in ZLIB format.
func (sf *StorageFormats) SaveAsZLIB(filename string, data []byte) error {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return ioutil.WriteFile(filename, b.Bytes(), 0644)
}

// LoadFromZLIB loads and decompresses the data from a ZLIB file.
func (sf *StorageFormats) LoadFromZLIB(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ioutil.ReadAll(r)
}

// saveToFile compresses, encrypts, and saves the data to a file.
func (sf *StorageFormats) saveToFile(filename string, data []byte) error {
	compressedData, err := compress(data)
	if err != nil {
		return err
	}

	encryptedData, err := encrypt(compressedData, sf.key)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, encryptedData, 0644)
}

// loadFromFile loads, decrypts, and decompresses the data from a file.
func (sf *StorageFormats) loadFromFile(filename string) ([]byte, error) {
	encryptedData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decrypt(encryptedData, sf.key)
	if err != nil {
		return nil, err
	}

	return decompress(decryptedData)
}

// compress compresses the given data using zlib.
func compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decompress decompresses the given data using zlib.
func decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

// generateKey derives a key from the given passphrase using Argon2.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, nil
}

// encrypt encrypts the given data with the provided key using AES.
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

// decrypt decrypts the given data with the provided key using AES.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// DirectoryBackup compresses, encrypts, and saves all files in a directory.
func (sf *StorageFormats) DirectoryBackup(directoryPath, backupFilePath string) error {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	err := filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(directoryPath, path)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		w, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		_, err = io.Copy(w, file)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := zipWriter.Close(); err != nil {
		return err
	}

	return sf.SaveAsBinary(backupFilePath, buf.Bytes())
}

// DirectoryRestore decrypts, decompresses, and restores all files to a directory.
func (sf *StorageFormats) DirectoryRestore(backupFilePath, restoreDirectoryPath string) error {
	data, err := sf.LoadFromBinary(backupFilePath)
	if err != nil {
		return err
	}

	buf := bytes.NewReader(data)
	zipReader, err := zip.NewReader(buf, int64(len(data)))
	if err != nil {
		return err
	}

	for _, file := range zipReader.File {
		path := filepath.Join(restoreDirectoryPath, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, os.ModePerm)
			continue
		}

		err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}

		rc, err := file.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)
		if err != nil {
			return err
		}

		outFile.Close()
		rc.Close
