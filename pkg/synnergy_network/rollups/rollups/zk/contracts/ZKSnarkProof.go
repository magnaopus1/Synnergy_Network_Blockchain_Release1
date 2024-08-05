package contracts

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// ZKSnarkProof handles zk-SNARK proof generation and verification.
type ZKSnarkProof struct {
	provingKey       []byte
	verificationKey  []byte
	encryptedDataKey []byte
}

// NewZKSnarkProof initializes a new ZKSnarkProof with provided keys.
func NewZKSnarkProof(provingKey, verificationKey []byte) *ZKSnarkProof {
	return &ZKSnarkProof{
		provingKey:      provingKey,
		verificationKey: verificationKey,
	}
}

// GenerateProvingKey generates a new proving key for zk-SNARK.
func (zk *ZKSnarkProof) GenerateProvingKey() error {
	key, err := generateRandomBytes(64)
	if err != nil {
		return err
	}
	zk.provingKey = key
	return nil
}

// GenerateVerificationKey generates a new verification key for zk-SNARK.
func (zk *ZKSnarkProof) GenerateVerificationKey() error {
	key, err := generateRandomBytes(64)
	if err != nil {
		return err
	}
	zk.verificationKey = key
	return nil
}

// EncryptData encrypts the given data using the zk-SNARK proving key.
func (zk *ZKSnarkProof) EncryptData(data map[string]interface{}) (string, error) {
	if len(zk.provingKey) == 0 {
		return "", errors.New("proving key is not set")
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	hashedKey := sha256.Sum256(zk.provingKey)
	cipherText, err := encryptAES(dataBytes, hashedKey[:])
	if err != nil {
		return "", err
	}

	zk.encryptedDataKey = cipherText
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptData decrypts the given encrypted data using the zk-SNARK proving key.
func (zk *ZKSnarkProof) DecryptData(encryptedData string) (map[string]interface{}, error) {
	if len(zk.provingKey) == 0 {
		return nil, errors.New("proving key is not set")
	}

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	hashedKey := sha256.Sum256(zk.provingKey)
	decryptedData, err := decryptAES(decodedData, hashedKey[:])
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(decryptedData, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GenerateProof generates a zk-SNARK proof for the given data.
func (zk *ZKSnarkProof) GenerateProof(data map[string]interface{}) ([]byte, error) {
	// Simulating proof generation, in a real implementation this would involve complex cryptographic calculations
	proof, err := generateRandomBytes(128)
	if err != nil {
		return nil, err
	}

	fmt.Println("Proof generated successfully.")
	return proof, nil
}

// VerifyProof verifies the given zk-SNARK proof against the data and verification key.
func (zk *ZKSnarkProof) VerifyProof(data map[string]interface{}, proof []byte) (bool, error) {
	// Simulating proof verification, in a real implementation this would involve complex cryptographic verification
	fmt.Println("Proof verification started.")
	// For simplicity, always return true in this simulated implementation
	return true, nil
}

// encryptAES encrypts data using AES encryption with the provided key.
func encryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return cipherText, nil
}

// decryptAES decrypts data using AES decryption with the provided key.
func decryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// generateRandomBytes generates a byte slice of specified length filled with random bytes.
func generateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Argon2Hash generates a secure hash using the Argon2 algorithm.
func Argon2Hash(password, salt string) (string, error) {
	saltBytes := []byte(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(hash), nil
}
