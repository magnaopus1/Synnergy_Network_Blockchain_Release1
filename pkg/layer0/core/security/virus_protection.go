package security

import (
    "crypto/sha256"
    "errors"
    "io/ioutil"
    "os"
    "path/filepath"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    Salt       = "your-unique-salt"
    KeyLength  = 32
    ScryptN    = 16384
    ScryptR    = 8
    ScryptP    = 1
    ArgonTime  = 1
    ArgonMemory = 64 * 1024
    ArgonThreads = 4
)

// FileSignature represents a file and its SHA-256 hash
type FileSignature struct {
    Path string
    Hash []byte
}

// ScanDirectory recursively scans a directory for files and calculates their SHA-256 hash
func ScanDirectory(dirPath string) ([]FileSignature, error) {
    var signatures []FileSignature
    err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() {
            hash, err := hashFile(path)
            if err != nil {
                return err
            }
            signatures = append(signatures, FileSignature{Path: path, Hash: hash})
        }
        return nil
    })
    if err != nil {
        return nil, err
    }
    return signatures, nil
}

// hashFile computes the SHA-256 hash of a file
func hashFile(filePath string) ([]byte, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    hasher := sha256.New()
    if _, err := io.Copy(hasher, file); err != nil {
        return nil, err
    }

    return hasher.Sum(nil), nil
}

// EncryptData uses Argon2 to encrypt data
func EncryptData(data []byte) ([]byte, error) {
    salt := []byte(Salt)
    return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLength), nil
}

// DecryptData uses Scrypt to decrypt data
func DecryptData(encryptedData, salt []byte) ([]byte, error) {
    return scrypt.Key(encryptedData, salt, ScryptN, ScryptR, ScryptP, KeyLength)
}

// DetectMalware compares file hashes against a list of known malware signatures
func DetectMalware(signatures []FileSignature, malwareHashes [][]byte) []string {
    var infectedFiles []string
    for _, signature := range signatures {
        for _, malwareHash := range malwareHashes {
            if bytes.Equal(signature.Hash, malwareHash) {
                infectedFiles = append(infectedFiles, signature.Path)
                break
            }
        }
    }
    return infectedFiles
}

// main function to initiate the virus protection process
func main() {
    // Example directory and malware hashes
    directoryToScan := "/path/to/scan"
    knownMalwareHashes := [][]byte{[]byte{0x12, 0x34}} // Example malware hashes

    signatures, err := ScanDirectory(directoryToScan)
    if err != nil {
        log.Fatal(err)
    }

    infectedFiles := DetectMalware(signatures, knownMalwareHashes)
    for _, file := range infectedFiles {
        fmt.Println("Infected file detected:", file)
    }
}
