package ai

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "os"
    "time"

    "golang.org/x/crypto/argon2"
)

const (
    licenseFile = "licenses.json"
)

type License struct {
    ID             string    `json:"id"`
    IssuedTo       string    `json:"issued_to"`
    IssuedAt       time.Time `json:"issued_at"`
    ExpiresAt      time.Time `json:"expires_at"`
    Terms          string    `json:"terms"`
    Fee            float64   `json:"fee"`
    AutoRenew      bool      `json:"auto_renew"`
    LastChecked    time.Time `json:"last_checked"`
}

var licenses = make(map[string]License)

func InitLicenses() error {
    file, err := os.Open(licenseFile)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return err
    }
    defer file.Close()
    return json.NewDecoder(file).Decode(&licenses)
}

func SaveLicenses() error {
    file, err := os.Create(licenseFile)
    if err != nil {
        return err
    }
    defer file.Close()
    return json.NewEncoder(file).Encode(&licenses)
}

func Encrypt(data []byte, passphrase string) ([]byte, error) {
    block, err := aes.NewCipher([]byte(passphrase))
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

func Decrypt(data []byte, passphrase string) ([]byte, error) {
    block, err := aes.NewCipher([]byte(passphrase))
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

func HashPassword(password string) (string, []byte, error) {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", nil, err
    }
    hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return fmt.Sprintf("%x", hash), salt, nil
}

func VerifyPassword(password string, hash string, salt []byte) bool {
    newHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return fmt.Sprintf("%x", newHash) == hash
}

func IssueLicense(id, issuedTo, terms string, fee float64, duration time.Duration, autoRenew bool) (*License, error) {
    if _, exists := licenses[id]; exists {
        return nil, errors.New("license with this ID already exists")
    }
    license := License{
        ID:             id,
        IssuedTo:       issuedTo,
        IssuedAt:       time.Now(),
        ExpiresAt:      time.Now().Add(duration),
        Terms:          terms,
        Fee:            fee,
        AutoRenew:      autoRenew,
        LastChecked:    time.Now(),
    }
    licenses[id] = license
    return &license, SaveLicenses()
}

func RevokeLicense(id string) error {
    if _, exists := licenses[id]; !exists {
        return errors.New("license not found")
    }
    delete(licenses, id)
    return SaveLicenses()
}

func RenewLicense(id string) (*License, error) {
    license, exists := licenses[id]
    if !exists {
        return nil, errors.New("license not found")
    }
    if !license.AutoRenew {
        return nil, errors.New("auto-renew is not enabled for this license")
    }
    license.ExpiresAt = time.Now().AddDate(1, 0, 0)
    license.LastChecked = time.Now()
    licenses[id] = license
    return &license, SaveLicenses()
}

func CheckAndRenewLicenses() error {
    now := time.Now()
    for id, license := range licenses {
        if license.ExpiresAt.Before(now) && license.AutoRenew {
            if _, err := RenewLicense(id); err != nil {
                log.Printf("failed to renew license %s: %v", id, err)
            }
        }
        licenses[id] = license
    }
    return SaveLicenses()
}

func main() {
    if err := InitLicenses(); err != nil {
        log.Fatalf("failed to initialize licenses: %v", err)
    }

    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()

    for range ticker.C {
        if err := CheckAndRenewLicenses(); err != nil {
            log.Printf("error checking and renewing licenses: %v", err)
        }
    }
}
