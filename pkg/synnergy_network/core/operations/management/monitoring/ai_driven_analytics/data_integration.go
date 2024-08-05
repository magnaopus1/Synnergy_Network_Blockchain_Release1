package ai_driven_analytics

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "io"
    "log"
    "time"

    "golang.org/x/crypto/scrypt"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

// DataIntegrationService encapsulates the methods and functionalities for data integration
type DataIntegrationService struct {
    db *gorm.DB
    encryptionKey []byte
}

// DataRecord represents a generic data record
type DataRecord struct {
    ID        uint      `gorm:"primaryKey"`
    CreatedAt time.Time
    UpdatedAt time.Time
    Data      string
}

// NewDataIntegrationService creates a new instance of DataIntegrationService
func NewDataIntegrationService(dsn string, encryptionKey []byte) (*DataIntegrationService, error) {
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        return nil, err
    }

    if err := db.AutoMigrate(&DataRecord{}); err != nil {
        return nil, err
    }

    return &DataIntegrationService{db: db, encryptionKey: encryptionKey}, nil
}

// Encrypt encrypts plain text string into cipher text using AES-GCM
func Encrypt(plainText, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    cipherText := aesGCM.Seal(nonce, nonce, plainText, nil)
    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts cipher text string into plain text using AES-GCM
func Decrypt(cipherText string, key []byte) (string, error) {
    cipherData, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := aesGCM.NonceSize()
    if len(cipherData) < nonceSize {
        return "", errors.New("cipher text too short")
    }

    nonce, cipherText := cipherData[:nonceSize], cipherData[nonceSize:]
    plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
    if err != nil {
        return "", err
    }

    return string(plainText), nil
}

// SaveData saves a new data record to the database with encryption
func (s *DataIntegrationService) SaveData(ctx context.Context, plainText string) error {
    encryptedData, err := Encrypt([]byte(plainText), s.encryptionKey)
    if err != nil {
        return err
    }

    dataRecord := DataRecord{
        Data: encryptedData,
    }

    return s.db.WithContext(ctx).Create(&dataRecord).Error
}

// RetrieveData retrieves a data record from the database and decrypts it
func (s *DataIntegrationService) RetrieveData(ctx context.Context, id uint) (string, error) {
    var dataRecord DataRecord
    if err := s.db.WithContext(ctx).First(&dataRecord, id).Error; err != nil {
        return "", err
    }

    decryptedData, err := Decrypt(dataRecord.Data, s.encryptionKey)
    if err != nil {
        return "", err
    }

    return decryptedData, nil
}

// generateEncryptionKey generates a secure encryption key using Scrypt
func generateEncryptionKey(passphrase, salt []byte) ([]byte, error) {
    const keyLen = 32
    key, err := scrypt.Key(passphrase, salt, 1<<15, 8, 1, keyLen)
    if err != nil {
        return nil, err
    }
    return key, nil
}

func main() {
    passphrase := []byte("supersecurepassword")
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        log.Fatal(err)
    }

    encryptionKey, err := generateEncryptionKey(passphrase, salt)
    if err != nil {
        log.Fatal(err)
    }

    dsn := "user=postgres password=yourpassword dbname=yourdb sslmode=disable"
    dataService, err := NewDataIntegrationService(dsn, encryptionKey)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Save data
    err = dataService.SaveData(ctx, "This is a test data")
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve data
    data, err := dataService.RetrieveData(ctx, 1)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Retrieved Data:", data)
}
