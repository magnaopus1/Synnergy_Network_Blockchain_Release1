package security_scanning

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "sync"
    "time"
    "encoding/json"
    "crypto/sha256"
    "io/ioutil"
    "log"
    "github.com/synnergy_network/encryption"
    "github.com/synnergy_network/logger"
)

// DependencyScanner is a struct for managing dependency scanning
type DependencyScanner struct {
    projectDir    string
    reportDir     string
    vulnerableLibs map[string]string
    mu            sync.Mutex
}

// NewDependencyScanner creates a new instance of DependencyScanner
func NewDependencyScanner(projectDir, reportDir string) *DependencyScanner {
    return &DependencyScanner{
        projectDir:    projectDir,
        reportDir:     reportDir,
        vulnerableLibs: make(map[string]string),
    }
}

// ScanDependencies scans the project directory for vulnerable dependencies
func (ds *DependencyScanner) ScanDependencies() error {
    logger.Info("Starting dependency scan...")
    
    files, err := ds.getFilesWithDependencies()
    if err != nil {
        return fmt.Errorf("failed to get dependency files: %w", err)
    }
    
    var wg sync.WaitGroup
    for _, file := range files {
        wg.Add(1)
        go func(file string) {
            defer wg.Done()
            if err := ds.scanFile(file); err != nil {
                logger.Error(fmt.Sprintf("Failed to scan file %s: %v", file, err))
            }
        }(file)
    }
    wg.Wait()

    if err := ds.generateReport(); err != nil {
        return fmt.Errorf("failed to generate report: %w", err)
    }

    logger.Info("Dependency scan completed.")
    return nil
}

// getFilesWithDependencies retrieves all files with dependencies in the project directory
func (ds *DependencyScanner) getFilesWithDependencies() ([]string, error) {
    var files []string
    err := filepath.Walk(ds.projectDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() && (strings.HasSuffix(path, "package.json") || strings.HasSuffix(path, "requirements.txt")) {
            files = append(files, path)
        }
        return nil
    })
    return files, err
}

// scanFile scans a specific dependency file for vulnerabilities
func (ds *DependencyScanner) scanFile(file string) error {
    logger.Info(fmt.Sprintf("Scanning file: %s", file))
    
    cmd := exec.Command("snyk", "test", "--file="+file)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed to execute snyk command: %w", err)
    }
    
    ds.parseScanResults(file, output)
    return nil
}

// parseScanResults parses the results from a scan and updates the vulnerableLibs map
func (ds *DependencyScanner) parseScanResults(file string, output []byte) {
    ds.mu.Lock()
    defer ds.mu.Unlock()

    var result map[string]interface{}
    if err := json.Unmarshal(output, &result); err != nil {
        logger.Error(fmt.Sprintf("Failed to parse JSON output for file %s: %v", file, err))
        return
    }

    vulnerabilities, ok := result["vulnerabilities"].([]interface{})
    if !ok {
        logger.Error(fmt.Sprintf("No vulnerabilities found in file %s", file))
        return
    }

    for _, vuln := range vulnerabilities {
        if v, ok := vuln.(map[string]interface{}); ok {
            lib := v["packageName"].(string)
            severity := v["severity"].(string)
            ds.vulnerableLibs[lib] = severity
        }
    }
}

// generateReport generates a report of the vulnerabilities found
func (ds *DependencyScanner) generateReport() error {
    reportFile := filepath.Join(ds.reportDir, fmt.Sprintf("dependency_scan_report_%s.json", time.Now().Format("20060102_150405")))
    reportData, err := json.MarshalIndent(ds.vulnerableLibs, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal report data: %w", err)
    }

    if err := ioutil.WriteFile(reportFile, reportData, 0644); err != nil {
        return fmt.Errorf("failed to write report file: %w", err)
    }

    logger.Info(fmt.Sprintf("Report generated: %s", reportFile))
    return nil
}

// SecureDependencyFile hashes the dependency file and encrypts it using AES
func (ds *DependencyScanner) SecureDependencyFile(file string) error {
    data, err := ioutil.ReadFile(file)
    if err != nil {
        return fmt.Errorf("failed to read file %s: %w", file, err)
    }

    hash := sha256.Sum256(data)
    encryptedData, err := encryption.AESEncrypt(data, hash[:])
    if err != nil {
        return fmt.Errorf("failed to encrypt file %s: %w", file, err)
    }

    if err := ioutil.WriteFile(file+".enc", encryptedData, 0644); err != nil {
        return fmt.Errorf("failed to write encrypted file %s: %w", file, err)
    }

    logger.Info(fmt.Sprintf("File secured: %s.enc", file))
    return nil
}

