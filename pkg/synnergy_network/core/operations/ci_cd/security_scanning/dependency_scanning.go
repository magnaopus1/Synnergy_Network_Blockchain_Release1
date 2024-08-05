package security_scanning

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"os"
	"os/exec"
	"strings"
)

// DependencyScanner defines the structure for dependency scanning
type DependencyScanner struct {
	DependencyFilePath string
	Vulnerabilities    []string
}

// NewDependencyScanner creates a new instance of DependencyScanner
func NewDependencyScanner(dependencyFilePath string) *DependencyScanner {
	return &DependencyScanner{
		DependencyFilePath: dependencyFilePath,
		Vulnerabilities:    []string{},
	}
}

// ScanDependencies scans the dependencies for known vulnerabilities
func (ds *DependencyScanner) ScanDependencies() error {
	if _, err := os.Stat(ds.DependencyFilePath); os.IsNotExist(err) {
		return errors.New("dependency file does not exist")
	}

	// Example scan command for npm dependencies. This should be replaced with the appropriate command for the given environment.
	cmd := exec.Command("npm", "audit", "--json")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Parse the output and collect vulnerabilities
	ds.Vulnerabilities = parseVulnerabilities(string(output))
	return nil
}

// parseVulnerabilities parses the output of the scan command and extracts vulnerabilities
func parseVulnerabilities(output string) []string {
	// This is a simplified example. Parsing should be adjusted based on the actual output format.
	var vulnerabilities []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "vulnerability") {
			vulnerabilities = append(vulnerabilities, line)
		}
	}
	return vulnerabilities
}

// EncryptVulnerabilityReport encrypts the vulnerability report using Argon2
func (ds *DependencyScanner) EncryptVulnerabilityReport() (string, error) {
	report := strings.Join(ds.Vulnerabilities, "\n")
	salt, err := generateRandomSalt()
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(report), salt, 1, 64*1024, 4, 32)
	encryptedReport := hex.EncodeToString(hash)
	return encryptedReport, nil
}

// generateRandomSalt generates a random salt for encryption
func generateRandomSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// SaveReport saves the encrypted vulnerability report to a file
func (ds *DependencyScanner) SaveReport(report string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(report)
	if err != nil {
		return err
	}

	return nil
}

// PrintVulnerabilities prints the found vulnerabilities
func (ds *DependencyScanner) PrintVulnerabilities() {
	if len(ds.Vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	fmt.Println("Vulnerabilities found:")
	for _, vulnerability := range ds.Vulnerabilities {
		fmt.Println(vulnerability)
	}
}

// Example usage of the DependencyScanner
func main() {
	ds := NewDependencyScanner("path/to/dependency/file")
	err := ds.ScanDependencies()
	if err != nil {
		fmt.Println("Error scanning dependencies:", err)
		return
	}

	ds.PrintVulnerabilities()

	encryptedReport, err := ds.EncryptVulnerabilityReport()
	if err != nil {
		fmt.Println("Error encrypting report:", err)
		return
	}

	err = ds.SaveReport(encryptedReport, "path/to/encrypted/report")
	if err != nil {
		fmt.Println("Error saving report:", err)
		return
	}

	fmt.Println("Vulnerability report encrypted and saved successfully.")
}
