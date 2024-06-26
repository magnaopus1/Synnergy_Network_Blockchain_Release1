package analytics

import (
    "bytes"
    "encoding/json"
    "log"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// Constants for encryption
const (
    Salt       = "secure-random-salt"  // This should be securely stored and generated uniquely for production
    KeyLength  = 32
    ArgonTime  = 1
    ArgonMemory = 64 * 1024
    ArgonThreads = 4
    ScryptN    = 16384
    ScryptR    = 8
    ScryptP    = 1
)

// ReportData holds data for reports
type ReportData struct {
    Timestamp   time.Time
    DataType    string
    DataContent json.RawMessage
}

// ReportGenerator is responsible for generating and encrypting reports
type ReportGenerator struct {
    reports []ReportData
}

// NewReportGenerator creates a new instance of ReportGenerator
func NewReportGenerator() *ReportGenerator {
    return &ReportGenerator{}
}

// AddReport adds a new report to the generator
func (rg *ReportGenerator) AddReport(dataType string, data interface{}) error {
    jsonData, err := json.Marshal(data)
    if err != nil {
        log.Printf("Failed to marshal data: %v", err)
        return err
    }

    rg.reports = append(rg.reports, ReportData{
        Timestamp:   time.Now(),
        DataType:    dataType,
        DataContent: jsonData,
    })
    return nil
}

// GenerateEncryptedReport encrypts the current batch of reports
func (rg *ReportGenerator) GenerateEncryptedReport(useArgon bool) ([]byte, error) {
    var encryptedData []byte
    var err error

    reportBytes, err := json.Marshal(rg.reports)
    if err != nil {
        log.Printf("Error marshaling reports: %v", err)
        return nil, err
    }

    if useArgon {
        encryptedData = argon2.IDKey(reportBytes, []byte(Salt), ArgonTime, ArgonMemory, ArgonThreads, KeyLength)
    } else {
        encryptedData, err = scrypt.Key(reportBytes, []byte(Salt), ScryptN, ScryptR, ScryptP, KeyLength)
        if err != nil {
            log.Printf("Error encrypting data with Scrypt: %v", err)
            return nil, err
        }
    }

    return encryptedData, nil
}

// DisplayReports logs all current reports
func (rg *ReportGenerator) DisplayReports() {
    for _, report := range rg.reports {
        log.Printf("Report - Time: %v, Type: %s, Content: %s", report.Timestamp, report.DataType, report.DataContent)
    }
}

// main function to initiate report generation and display
func main() {
    rg := NewReportGenerator()
    rg.AddReport("TransactionAnalysis", TransactionAnalysis{time.Now(), "tx789", "addressX", "addressY", 500.0})
    rg.AddReport("BehaviorMetrics", BehaviorMetrics{"user2", 20, 10, 2000.0})

    encryptedReport, err := rg.GenerateEncryptedReport(true)
    if err != nil {
        log.Fatalf("Failed to generate encrypted report: %v", err)
    }
    log.Printf("Encrypted Report: %x", encryptedReport)

    rg.DisplayReports()
}
