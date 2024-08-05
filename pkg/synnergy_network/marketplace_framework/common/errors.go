package common

import (
    "errors"
    "fmt"
    "net/http"
    "runtime"
    "strings"
    "sync"
)

// CustomError structure to define a comprehensive error type
type CustomError struct {
    Code    int
    Message string
    Err     error
    Stack   string
}

var (
    errorMap  = make(map[int]string)
    errorLock sync.RWMutex
)

// RegisterError function to register custom error messages with their codes
func RegisterError(code int, message string) {
    errorLock.Lock()
    defer errorLock.Unlock()
    errorMap[code] = message
}

// NewCustomError creates a new CustomError
func NewCustomError(code int, err error) *CustomError {
    return &CustomError{
        Code:    code,
        Message: errorMap[code],
        Err:     err,
        Stack:   captureStackTrace(),
    }
}

// Error returns the error message
func (e *CustomError) Error() string {
    if e.Err != nil {
        return fmt.Sprintf("Code: %d, Message: %s, Error: %s, Stack: %s", e.Code, e.Message, e.Err.Error(), e.Stack)
    }
    return fmt.Sprintf("Code: %d, Message: %s, Stack: %s", e.Code, e.Message, e.Stack)
}

// captureStackTrace captures the current stack trace
func captureStackTrace() string {
    stackBuf := make([]byte, 1024)
    stackBuf = stackBuf[:runtime.Stack(stackBuf, false)]
    return strings.TrimSpace(string(stackBuf))
}

// WrapError wraps an existing error into a CustomError with a specific code
func WrapError(code int, err error) *CustomError {
    return NewCustomError(code, err)
}

// HTTPErrorMapper maps CustomError codes to HTTP status codes
func HTTPErrorMapper(err error) int {
    if customErr, ok := err.(*CustomError); ok {
        switch customErr.Code {
        case 1000:
            return http.StatusBadRequest
        case 1001:
            return http.StatusUnauthorized
        case 1002:
            return http.StatusForbidden
        case 1003:
            return http.StatusNotFound
        case 1004:
            return http.StatusConflict
        case 1005:
            return http.StatusInternalServerError
        default:
            return http.StatusInternalServerError
        }
    }
    return http.StatusInternalServerError
}

// IsCustomError checks if an error is a CustomError
func IsCustomError(err error) bool {
    _, ok := err.(*CustomError)
    return ok
}

// Predefined errors
var (
    ErrNotFound             = NewCustomError(1003, errors.New("resource not found"))
    ErrUnauthorized         = NewCustomError(1001, errors.New("unauthorized access"))
    ErrBadRequest           = NewCustomError(1000, errors.New("bad request"))
    ErrInternalServer       = NewCustomError(1005, errors.New("internal server error"))
    ErrConflict             = NewCustomError(1004, errors.New("resource conflict"))
    ErrForbidden            = NewCustomError(1002, errors.New("forbidden access"))
)

func init() {
    // Registering custom errors with their respective messages
    RegisterError(1000, "Bad Request")
    RegisterError(1001, "Unauthorized Access")
    RegisterError(1002, "Forbidden Access")
    RegisterError(1003, "Resource Not Found")
    RegisterError(1004, "Resource Conflict")
    RegisterError(1005, "Internal Server Error")
}
