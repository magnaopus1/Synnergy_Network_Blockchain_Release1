package interledger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockInterledgerConfig to simulate interledger configurations for testing
type MockInterledgerConfig struct {
	mock.Mock
	InterledgerConfig
}

// SetupMock initializes default values for testing the interledger config
func (m *MockInterledgerConfig) SetupMock() {
	m.On("SetupCipher").Return(mock.Anything, nil) // Simulate successful cipher setup
}

// TestNewInterledgerConfig tests the configuration initialization
func TestNewInterledgerConfig(t *testing.T) {
	config, err := NewInterledgerConfig("securepassphrase")
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Len(t, config.Salt, 16)
}

// TestInterledgerEncryptionDecryption tests the encryption and decryption to ensure they are complementary
func TestInterledgerEncryptionDecryption(t *testing.T) {
	config, _ := NewInterledgerConfig("securepassphrase")
	plaintext := "Hello, Interledger!"

	encryptedData, err := config.EncryptData([]byte(plaintext))
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, encryptedData)

	decryptedData, err := config.DecryptData(encryptedData)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, string(decryptedData))
}

// TestInterledgerCipherSetup tests the cipher setup for any configuration errors
func TestInterledgerCipherSetup(t *testing.T) {
	config := &InterledgerConfig{
		Passphrase: "securepassphrase",
		Salt:       make([]byte, 16),
	}

	_, err := config.SetupCipher()
	assert.NoError(t, err)
}

// BenchmarkInterledgerEncryption benchmarks the encryption performance
func BenchmarkInterledgerEncryption(b *testing.B) {
	config, _ := NewInterledgerConfig("securepassphrase")
	for i := 0; i < b.N; i++ {
		config.EncryptData([]byte("benchmarking interledger encryption"))
	}
}

// BenchmarkInterledgerDecryption benchmarks the decryption performance
func BenchmarkInterledgerDecryption(b *testing.B) {
	config, _ := NewInterledgerConfig("securepassphrase")
	encryptedData, _ := config.EncryptData([]byte("benchmarking interledger decryption"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.DecryptData(encryptedData)
	}
}
