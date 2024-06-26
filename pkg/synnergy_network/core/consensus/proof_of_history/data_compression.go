package proof_of_history

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io/ioutil"

	"github.com/synthron/synthronchain/crypto"
)

// CompressData takes raw data and returns a gzip compressed, base64 encoded string
func CompressData(data []byte) (string, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return "", err
	}
	if err := gz.Flush(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// DecompressData takes a compressed, base64 encoded string and returns the original data
func DecompressData(compressed string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(compressed)
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	decompressed, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return decompressed, nil
}

// HashData creates a cryptographic hash of the data using SHA-256
func HashData(data []byte) string {
	return crypto.SHA256Hash(data)
}

// InitializeDataProcessing demonstrates initializing data processing in PoH
func InitializeDataProcessing(data string) {
	// Simulate transaction data compression and hashing as part of PoH
	compressedData, err := CompressData([]byte(data))
	if err != nil {
		panic(err)
	}

	hash := HashData([]byte(compressedData))
	println("Compressed Data: ", compressedData)
	println("Hash of Compressed Data: ", hash)
}

func main() {
	sampleData := "Synthron blockchain transaction data"
	InitializeDataProcessing(sampleData)
}
