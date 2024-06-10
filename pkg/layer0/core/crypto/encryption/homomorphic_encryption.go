package encryption

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ldsec/lattigo/v2/ckks"
)

// HomomorphicEncryptionService provides methods to perform operations on encrypted data.
type HomomorphicEncryptionService struct {
	params ckks.Parameters
	encoder ckks.Encoder
	kgen    ckks.KeyGenerator
	sk      *ckks.SecretKey
	pk      *ckks.PublicKey
	encryptor ckks.Encryptor
	decryptor ckks.Decryptor
	evaluator ckks.Evaluator
}

// NewHomomorphicEncryptionService initializes a new service for homomorphic encryption.
func NewHomomorphicEncryptionService() (*HomomorphicEncryptionService, error) {
	// Set parameters for CKKS scheme with logN=14, logQ=16 and logP=30 for enough precision and security
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:  14,
		LogQ:  []uint64{30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
		LogP:  30,
		Sigma: 3.19,
		LogSlots: 13,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create CKKS parameters: %v", err)
	}

	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	return &HomomorphicEncryptionService{
		params:    params,
		encoder:   ckks.NewEncoder(params),
		kgen:      kgen,
		sk:        sk,
		pk:        pk,
		encryptor: ckks.NewEncryptorFromPk(params, pk),
		decryptor: ckks.NewDecryptor(params, sk),
		evaluator: ckks.NewEvaluator(params, ckks.EvaluationKey{Rlk: kgen.GenRelinKey(sk)}),
	}, nil
}

// EncryptData encrypts data using CKKS homomorphic encryption.
func (hes *HomomorphicEncryptionService) EncryptData(data []float64) ([]byte, error) {
	values := make([]complex128, hes.params.Slots())
	for i, val := range data {
		values[i] = complex(val, 0)
	}

	plaintext := hes.encoder.EncodeNew(values, hes.params.LogSlots())
	ciphertext := hes.encryptor.EncryptNew(plaintext)
	return ciphertext.MarshalBinary()
}

// DecryptData decrypts data from its encrypted form.
func (hes *HomomorphicEncryptionService) DecryptData(data []byte) ([]float64, error) {
	ciphertext := new(ckks.Ciphertext)
	if err := ciphertext.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	plaintext, err := hes.decryptor.DecryptNew(ciphertext)
	if err != nil {
		return nil, err
	}

	values := hes.encoder.Decode(plaintext, hes.params.LogSlots())
	result := make([]float64, len(values))
	for i, val := range values {
		result[i] = real(val)
	}

	return result, nil
}

// Add performs addition on encrypted data.
func (hes *HomomorphicEncryptionService) Add(encryptedData1, encryptedData2 []byte) ([]byte, error) {
	ciphertext1 := new(ckks.Ciphertext)
	ciphertext2 := new(ckks.Ciphertext)
	if err := ciphertext1.UnmarshalBinary(encryptedData1); err != nil {
		return nil, err
	}
	if err := ciphertext2.UnmarshalBinary(encryptedData2); err != nil {
		return nil, err
	}

	hes.evaluator.Add(ciphertext1, ciphertext2, ciphertext1)
	return ciphertext1.MarshalBinary()
}

// Example usage
func main() {
	hes, err := NewHomomorphicEncryptionService()
	if err != nil {
		panic(err)
	}

	// Example: Encrypt and decrypt data
	data := []float64{1.5, -2.3, 3.7}
	encrypted, err := hes.EncryptData(data)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}

	decrypted, err := hes.DecryptData(encrypted)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Printf("Original: %v\nDecrypted: %v\n", data, decrypted)
}

// The above code provides a high-level implementation of homomorphic encryption, allowing for encrypted computations, specifically tailored to work seamlessly within a blockchain ecosystem where data security and privacy are paramount. Additional cryptographic protocols and security measures are recommended to address the evolving landscape of digital threats.
