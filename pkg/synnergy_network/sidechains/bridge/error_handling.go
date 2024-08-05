package bridge

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/synnergy_network/bridge/transfer_logs"
)

// ErrorLevel defines the severity of the error
type ErrorLevel int

const (
    Info ErrorLevel = iota
    Warning
    Error
    Critical
)

// ErrorDetails represents the details of an error
type ErrorDetails struct {
    Timestamp   time.Time  `json:"timestamp"`
    Level       ErrorLevel `json:"level"`
    Message     string     `json:"message"`
    StackTrace  string     `json:"stack_trace"`
    ContextInfo string     `json:"context_info"`
}

// ErrorHandler manages error logging and reporting
type ErrorHandler struct {
    logFile   *os.File
    logErrors []ErrorDetails
}

// NewErrorHandler creates a new ErrorHandler
func NewErrorHandler(logFilePath string) (*ErrorHandler, error) {
    logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }

    return &ErrorHandler{
        logFile:   logFile,
        logErrors: []ErrorDetails{},
    }, nil
}

// LogError logs an error with specified details
func (eh *ErrorHandler) LogError(level ErrorLevel, message, stackTrace, contextInfo string) {
    errorDetails := ErrorDetails{
        Timestamp:   time.Now(),
        Level:       level,
        Message:     message,
        StackTrace:  stackTrace,
        ContextInfo: contextInfo,
    }

    eh.logErrors = append(eh.logErrors, errorDetails)
    transfer_logs.LogError(errorDetails)
    eh.writeErrorToFile(errorDetails)
}

// writeErrorToFile writes error details to the log file
func (eh *ErrorHandler) writeErrorToFile(errorDetails ErrorDetails) {
    logEntry, err := json.Marshal(errorDetails)
    if err != nil {
        log.Printf("Failed to marshal error details: %v", err)
        return
    }

    if _, err := eh.logFile.Write(logEntry); err != nil {
        log.Printf("Failed to write to log file: %v", err)
    }
}

// Close closes the log file
func (eh *ErrorHandler) Close() error {
    return eh.logFile.Close()
}

// GenerateReport generates a detailed report of all logged errors
func (eh *ErrorHandler) GenerateReport() (string, error) {
    report, err := json.MarshalIndent(eh.logErrors, "", "  ")
    if err != nil {
        return "", err
    }
    return string(report), nil
}

// SendAlert sends an alert for critical errors
func (eh *ErrorHandler) SendAlert(errorDetails ErrorDetails) {
    if errorDetails.Level == Critical {
        // Implementation for sending alert (e.g., email, SMS, etc.)
        fmt.Printf("Critical alert: %s\n", errorDetails.Message)
    }
}

// Comprehensive example of error handling usage
func ExampleComprehensiveErrorHandling() {
    eh, err := NewErrorHandler("errors.log")
    if err != nil {
        log.Fatalf("Failed to create error handler: %v", err)
    }
    defer eh.Close()

    // Log an info message
    eh.LogError(Info, "This is an informational message", "", "Context info for info message")

    // Log a warning message
    eh.LogError(Warning, "This is a warning message", "", "Context info for warning message")

    // Log an error message
    eh.LogError(Error, "This is an error message", "Stack trace for error", "Context info for error message")

    // Log a critical message and send an alert
    criticalError := ErrorDetails{
        Timestamp:   time.Now(),
        Level:       Critical,
        Message:     "This is a critical error",
        StackTrace:  "Stack trace for critical error",
        ContextInfo: "Context info for critical error",
    }
    eh.LogError(criticalError.Level, criticalError.Message, criticalError.StackTrace, criticalError.ContextInfo)
    eh.SendAlert(criticalError)

    // Generate and print error report
    report, err := eh.GenerateReport()
    if err != nil {
        log.Fatalf("Failed to generate error report: %v", err)
    }
    fmt.Println("Error Report:", report)
}
