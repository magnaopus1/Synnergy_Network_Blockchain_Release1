package resource_markets

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "fmt"
    "io"
    "github.com/synnergy_network/core/resource_security"
)

// Resource represents an individual resource with a type, quantity, and value
type Resource struct {
    ResourceType string  // Type of resource
    Quantity     float64 // Quantity of the resource
    Value        float64 // Value per unit of the resource
}

// ResourceBundle represents a collection of resources bundled together
type ResourceBundle struct {
    BundleID   string     // Unique identifier for the bundle
    Resources  []Resource // List of resources in the bundle
    TotalValue float64    // Total value of all resources in the bundle
}

// CreateBundle initializes a new resource bundle
func CreateBundle(bundleID string, resources []Resource) *ResourceBundle {
    bundle := &ResourceBundle{
        BundleID:  bundleID,
        Resources: resources,
    }
    bundle.UpdateTotalValue()
    return bundle
}

// AddResource adds a resource to the bundle
func (rb *ResourceBundle) AddResource(resource Resource) {
    rb.Resources = append(rb.Resources, resource)
    rb.UpdateTotalValue()
}

// RemoveResource removes a resource from the bundle
func (rb *ResourceBundle) RemoveResource(resourceType string) error {
    for i, res := range rb.Resources {
        if res.ResourceType == resourceType {
            rb.Resources = append(rb.Resources[:i], rb.Resources[i+1:]...)
            rb.UpdateTotalValue()
            return nil
        }
    }
    return fmt.Errorf("resource not found")
}

// GetBundleValue calculates the total value of the bundle
func (rb *ResourceBundle) GetBundleValue() float64 {
    return rb.TotalValue
}

// UpdateTotalValue updates the total value of the resources in the bundle
func (rb *ResourceBundle) UpdateTotalValue() {
    totalValue := 0.0
    for _, res := range rb.Resources {
        totalValue += res.Quantity * res.Value
    }
    rb.TotalValue = totalValue
}

// TransferBundle handles the transfer of a resource bundle to another entity
func TransferBundle(from, to string, bundle *ResourceBundle) error {
    // Implement the transfer logic, including security checks and ledger updates
    // This function would interact with the blockchain to record the transfer
    fmt.Printf("Transferring bundle %s from %s to %s\n", bundle.BundleID, from, to)
    return nil
}

// EncryptBundle encrypts the bundle details using AES encryption
func (rb *ResourceBundle) EncryptBundle(key []byte) ([]byte, error) {
    plainText, err := json.Marshal(rb)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    cipherText := make([]byte, aes.BlockSize+len(plainText))
    iv := cipherText[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

    return cipherText, nil
}

// DecryptBundle decrypts the bundle details using AES encryption
func DecryptBundle(cipherText, key []byte) (*ResourceBundle, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(cipherText) < aes.BlockSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    iv := cipherText[:aes.BlockSize]
    cipherText = cipherText[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(cipherText, cipherText)

    var rb ResourceBundle
    err = json.Unmarshal(cipherText, &rb)
    if err != nil {
        return nil, err
    }

    return &rb, nil
}

// AuditBundle verifies the integrity and composition of the bundle
func AuditBundle(rb *ResourceBundle) error {
    // Implement audit logic to verify that the bundle's reported value matches the actual value
    // This could include cryptographic verification of each resource's authenticity
    fmt.Printf("Auditing bundle %s\n", rb.BundleID)
    return nil
}
