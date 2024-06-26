package quantum_computing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAddNode(t *testing.T) {
	rm := NewResourceManager()
	err := rm.AddNode("node1", 100)
	assert.Nil(t, err, "Adding node should not produce an error")
	assert.Equal(t, 1, len(rm.nodes), "Node count should be 1")

	err = rm.AddNode("node1", 100)
	assert.NotNil(t, err, "Adding the same node should produce an error")
}

func TestRemoveNode(t *testing.T) {
	rm := NewResourceManager()
	rm.AddNode("node1", 100)
	err := rm.RemoveNode("node1")
	assert.Nil(t, err, "Removing node should not produce an error")
	assert.Equal(t, 0, len(rm.nodes), "Node count should be 0")

	err = rm.RemoveNode("node1")
	assert.NotNil(t, err, "Removing a non-existent node should produce an error")
}

func TestAllocateJob(t *testing.T) {
	rm := NewResourceManager()
	rm.AddNode("node1", 100)
	algorithm := QuantumAlgorithm{
		Name: "Grover's Search",
		Params: map[string]interface{}{
			"search_space": 1000000,
			"target":       "needle",
		},
	}
	jobID, err := rm.AllocateJob(algorithm, "example_data")
	assert.Nil(t, err, "Allocating job should not produce an error")
	assert.NotEmpty(t, jobID, "Job ID should not be empty")
}

func TestProcessJob(t *testing.T) {
	rm := NewResourceManager()
	rm.AddNode("node1", 100)
	algorithm := QuantumAlgorithm{
		Name: "Grover's Search",
		Params: map[string]interface{}{
			"search_space": 1000000,
			"target":       "needle",
		},
	}
	jobID, err := rm.AllocateJob(algorithm, "example_data")
	assert.Nil(t, err, "Allocating job should not produce an error")

	result, err := rm.FetchJobResult(jobID)
	assert.Nil(t, err, "Fetching job result should not produce an error")
	assert.Contains(t, result.(string), "found needle", "Result should contain 'found needle'")
}

func TestExecuteAlgorithm(t *testing.T) {
	rm := NewResourceManager()
	algorithm := QuantumAlgorithm{
		Name: "Grover's Search",
		Params: map[string]interface{}{
			"search_space": 1000000,
			"target":       "needle",
		},
	}
	result, err := rm.executeAlgorithm(algorithm, "example_data")
	assert.Nil(t, err, "Executing algorithm should not produce an error")
	assert.Contains(t, result.(string), "found needle", "Result should contain 'found needle'")

	algorithm.Name = "Shor's Factoring"
	algorithm.Params = map[string]interface{}{
		"number": 1234567890,
	}
	result, err = rm.executeAlgorithm(algorithm, "example_data")
	assert.Nil(t, err, "Executing algorithm should not produce an error")
	assert.Contains(t, result.(string), "factors of 1234567890", "Result should contain 'factors of 1234567890'")

	algorithm.Name = "Quantum Fourier Transform"
	algorithm.Params = map[string]interface{}{
		"size": 8,
	}
	result, err = rm.executeAlgorithm(algorithm, "example_data")
	assert.Nil(t, err, "Executing algorithm should not produce an error")
	assert.Contains(t, result.(string), "QFT result of size 8", "Result should contain 'QFT result of size 8'")
}

func TestEncryptDecryptData(t *testing.T) {
	key := []byte("a very very very very secret key") // 32 bytes
	data := []byte("some really really really long data to encrypt")
	encryptedData, err := EncryptData(data, key)
	assert.Nil(t, err, "Encrypting data should not produce an error")

	decryptedData, err := DecryptData(encryptedData, key)
	assert.Nil(t, err, "Decrypting data should not produce an error")
	assert.Equal(t, data, decryptedData, "Decrypted data should match original data")
}

func TestGenerateKey(t *testing.T) {
	password := "supersecretpassword"
	salt := []byte("somesalt")
	key, err := GenerateKey(password, salt)
	assert.Nil(t, err, "Generating key should not produce an error")
	assert.Equal(t, 32, len(key), "Generated key should be 32 bytes long")
}

func TestMain(t *testing.T) {
	rm := NewResourceManager()

	rm.AddNode("node1", 100)
	rm.AddNode("node2", 150)

	algorithms := QuantumAlgorithmExamples()

	for _, algorithm := range algorithms {
		jobID, err := rm.AllocateJob(algorithm, "example_data")
		assert.Nil(t, err, "Allocating job should not produce an error")

		result, err := rm.FetchJobResult(jobID)
		assert.Nil(t, err, "Fetching job result should not produce an error")
		assert.NotNil(t, result, "Result should not be nil")
	}
}
