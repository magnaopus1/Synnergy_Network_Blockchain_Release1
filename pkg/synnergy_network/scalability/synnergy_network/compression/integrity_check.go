package compression

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
)

// IntegrityCheck provides functionalities for data integrity verification.
type IntegrityCheck struct{}

// NewIntegrityCheck initializes the IntegrityCheck.
func NewIntegrityCheck() *IntegrityCheck {
	return &IntegrityCheck{}
}

// GenerateSHA256Hash generates a SHA-256 hash of the given data.
func (ic *IntegrityCheck) GenerateSHA256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifySHA256Hash verifies the SHA-256 hash of the given data.
func (ic *IntegrityCheck) VerifySHA256Hash(data []byte, hash string) bool {
	return ic.GenerateSHA256Hash(data) == hash
}

// GenerateCRC32Checksum generates a CRC32 checksum of the given data.
func (ic *IntegrityCheck) GenerateCRC32Checksum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// VerifyCRC32Checksum verifies the CRC32 checksum of the given data.
func (ic *IntegrityCheck) VerifyCRC32Checksum(data []byte, checksum uint32) bool {
	return ic.GenerateCRC32Checksum(data) == checksum
}

// GenerateCRC64Checksum generates a CRC64 checksum of the given data.
func (ic *IntegrityCheck) GenerateCRC64Checksum(data []byte) uint64 {
	table := crc64.MakeTable(crc64.ECMA)
	return crc64.Checksum(data, table)
}

// VerifyCRC64Checksum verifies the CRC64 checksum of the given data.
func (ic *IntegrityCheck) VerifyCRC64Checksum(data []byte, checksum uint64) bool {
	return ic.GenerateCRC64Checksum(data) == checksum
}

// SaveHashToFile saves the hash to a file.
func (ic *IntegrityCheck) SaveHashToFile(filename, hash string) error {
	return os.WriteFile(filename, []byte(hash), 0644)
}

// LoadHashFromFile loads the hash from a file.
func (ic *IntegrityCheck) LoadHashFromFile(filename string) (string, error) {
	hash, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// SaveChecksumToFile saves the checksum to a file.
func (ic *IntegrityCheck) SaveChecksumToFile(filename string, checksum uint64) error {
	return os.WriteFile(filename, []byte(fmt.Sprintf("%x", checksum)), 0644)
}

// LoadChecksumFromFile loads the checksum from a file.
func (ic *IntegrityCheck) LoadChecksumFromFile(filename string) (uint64, error) {
	checksumData, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	var checksum uint64
	_, err = fmt.Sscanf(string(checksumData), "%x", &checksum)
	if err != nil {
		return 0, err
	}
	return checksum, nil
}

// CheckFileIntegrity checks the integrity of a file using the specified hash algorithm.
func (ic *IntegrityCheck) CheckFileIntegrity(filename, hashAlgorithm string) (bool, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return false, err
	}

	var isValid bool
	switch hashAlgorithm {
	case "sha256":
		hashFile := filename + ".sha256"
		storedHash, err := ic.LoadHashFromFile(hashFile)
		if err != nil {
			return false, err
		}
		isValid = ic.VerifySHA256Hash(data, storedHash)
	case "crc32":
		checksumFile := filename + ".crc32"
		storedChecksum, err := ic.LoadChecksumFromFile(checksumFile)
		if err != nil {
			return false, err
		}
		isValid = ic.VerifyCRC32Checksum(data, uint32(storedChecksum))
	case "crc64":
		checksumFile := filename + ".crc64"
		storedChecksum, err := ic.LoadChecksumFromFile(checksumFile)
		if err != nil {
			return false, err
		}
		isValid = ic.VerifyCRC64Checksum(data, storedChecksum)
	default:
		return false, errors.New("unsupported hash algorithm")
	}

	return isValid, nil
}

// CreateFileHash creates and saves the hash of a file using the specified hash algorithm.
func (ic *IntegrityCheck) CreateFileHash(filename, hashAlgorithm string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	switch hashAlgorithm {
	case "sha256":
		hash := ic.GenerateSHA256Hash(data)
		hashFile := filename + ".sha256"
		return ic.SaveHashToFile(hashFile, hash)
	case "crc32":
		checksum := ic.GenerateCRC32Checksum(data)
		checksumFile := filename + ".crc32"
		return ic.SaveChecksumToFile(checksumFile, uint64(checksum))
	case "crc64":
		checksum := ic.GenerateCRC64Checksum(data)
		checksumFile := filename + ".crc64"
		return ic.SaveChecksumToFile(checksumFile, checksum)
	default:
		return errors.New("unsupported hash algorithm")
	}
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// VerifyFileIntegrity reads a file and compares its hash with the stored hash.
func (ic *IntegrityCheck) VerifyFileIntegrity(filePath, hashAlgorithm string) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	var storedHash string
	switch hashAlgorithm {
	case "sha256":
		storedHashFile := filePath + ".sha256"
		storedHash, err = ic.LoadHashFromFile(storedHashFile)
		if err != nil {
			return false, err
		}
		return ic.VerifySHA256Hash(data, storedHash), nil
	case "crc32":
		storedHashFile := filePath + ".crc32"
		storedChecksum, err := ic.LoadChecksumFromFile(storedHashFile)
		if err != nil {
			return false, err
		}
		return ic.VerifyCRC32Checksum(data, uint32(storedChecksum)), nil
	case "crc64":
		storedHashFile := filePath + ".crc64"
		storedChecksum, err := ic.LoadChecksumFromFile(storedHashFile)
		if err != nil {
			return false, err
		}
		return ic.VerifyCRC64Checksum(data, storedChecksum), nil
	default:
		return false, errors.New("unsupported hash algorithm")
	}
}

// GenerateFileHash generates and saves a hash for a file.
func (ic *IntegrityCheck) GenerateFileHash(filePath, hashAlgorithm string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var hash string
	switch hashAlgorithm {
	case "sha256":
		hash = ic.GenerateSHA256Hash(data)
		hashFile := filePath + ".sha256"
		return ic.SaveHashToFile(hashFile, hash)
	case "crc32":
		checksum := ic.GenerateCRC32Checksum(data)
		checksumFile := filePath + ".crc32"
		return ic.SaveChecksumToFile(checksumFile, uint64(checksum))
	case "crc64":
		checksum := ic.GenerateCRC64Checksum(data)
		checksumFile := filePath + ".crc64"
		return ic.SaveChecksumToFile(checksumFile, checksum)
	default:
		return errors.New("unsupported hash algorithm")
	}
}
