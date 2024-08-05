package virus

import (
    "fmt"
    "time"
    "crypto/sha256"
    "encoding/hex"
    "io/ioutil"
    "os"
    "path/filepath"
)

// VirusScanner defines the interface for virus scanning mechanisms
type VirusScanner interface {
    Scan(filePath string) (bool, error) // Returns true if a virus is detected
    Quarantine(filePath string) error  // Quarantines the infected file
    Alert(userID string, details string) error // Alerts the user about the virus detection
}

// DefaultVirusScanner is the default implementation of VirusScanner
type DefaultVirusScanner struct {
    // configuration fields if needed
}

// Scan checks the file for known virus signatures
func (v *DefaultVirusScanner) Scan(filePath string) (bool, error) {
    // Implement virus signature detection logic
    // For demonstration, using a simple hash comparison
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return false, err
    }

    hash := sha256.Sum256(data)
    hashString := hex.EncodeToString(hash[:])
    knownVirusHashes := map[string]bool{
        // Example virus signatures
        "examplehash1": true,
        "examplehash2": true,
    }

    if _, found := knownVirusHashes[hashString]; found {
        return true, nil
    }
    return false, nil
}

// Quarantine moves the infected file to a quarantine directory
func (v *DefaultVirusScanner) Quarantine(filePath string) error {
    quarantineDir := "/path/to/quarantine" // Define the quarantine path
    if err := os.MkdirAll(quarantineDir, os.ModePerm); err != nil {
        return err
    }

    fileName := filepath.Base(filePath)
    newFilePath := filepath.Join(quarantineDir, fileName)
    if err := os.Rename(filePath, newFilePath); err != nil {
        return err
    }
    return nil
}

// Alert sends an alert to the user about the virus detection
func (v *DefaultVirusScanner) Alert(userID string, details string) error {
    // Implement alert mechanism, e.g., send an email or push notification
    fmt.Printf("Alerting user %s: %s\n", userID, details)
    return nil
}

// MonitorSystem continuously scans the system for virus threats
func MonitorSystem(scanner VirusScanner, interval time.Duration) {
    for {
        // Example directory to scan
        files, _ := ioutil.ReadDir("/path/to/scan")

        for _, f := range files {
            infected, err := scanner.Scan(f.Name())
            if err != nil {
                fmt.Println("Error scanning file:", err)
                continue
            }
            if infected {
                scanner.Quarantine(f.Name())
                scanner.Alert("user@example.com", "Virus detected in "+f.Name())
            }
        }
        time.Sleep(interval)
    }
}

func main() {
    scanner := &DefaultVirusScanner{}
    MonitorSystem(scanner, 30*time.Minute) // Scan every 30 minutes
}
