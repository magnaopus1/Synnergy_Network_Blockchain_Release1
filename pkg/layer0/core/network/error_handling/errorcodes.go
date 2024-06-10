package errorhandling

import (
    "fmt"
    "log"
    "os"
)

// Custom error types based on the application's requirements.
type ErrorCode int

const (
    ErrCodeNetworkFailure ErrorCode = iota + 1
    ErrCodeTransactionFailed
    ErrCodeValidationFailed
    ErrCodePermissionDenied
)

// ErrorDetails provides structured metadata about errors.
type ErrorDetails struct {
    Code    ErrorCode
    Message string
    Details string
}

func (e *ErrorDetails) Error() string {
    return fmt.Sprintf("Error %d: %s - Details: %s", e.Code, e.Message, e.Details)
}

// Initialize error logging system.
var (
    errorLog *log.Logger
)

func init() {
    file, err := os.OpenFile("errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
    if err != nil {
        log.Fatal("Failed to open error log file:", err)
    }
    errorLog = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// LogError logs an error into the system log file.
func LogError(err error) {
    errorLog.Println(err)
}

// HandleError processes errors based on their type and severity.
func HandleError(err error) {
    switch e := err.(type) {
    case *ErrorDetails:
        LogError(err)
        switch e.Code {
        case ErrCodeNetworkFailure, ErrCodeTransactionFailed:
            // Attempt to recover or retry operation
            RecoverFromError(e)
        case ErrCodeValidationFailed, ErrCodePermissionDenied:
            // Inform the user or request correct input
            NotifyUser(e)
        }
    default:
        log.Println("Unhandled error type:", err)
    }
}

// RecoverFromError attempts to handle recoverable errors.
func RecoverFromError(err *ErrorDetails) {
    // Implement recovery logic based on error code.
    fmt.Println("Recovering from error:", err.Message)
}

// NotifyUser sends error details to the user or logs them if not recoverable.
func NotifyUser(err *ErrorDetails) {
    // User notification logic based on application context.
    fmt.Println("Error notification sent for error code:", err.Code)
}

