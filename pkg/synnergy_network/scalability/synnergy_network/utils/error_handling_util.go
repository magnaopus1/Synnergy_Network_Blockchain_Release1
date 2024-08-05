package error_handling_util

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

// CustomError defines a structured error with additional context.
type CustomError struct {
	Timestamp time.Time
	FuncName  string
	Message   string
	Details   string
}

func (e *CustomError) Error() string {
	return fmt.Sprintf("[%s] %s: %s - %s", e.Timestamp.Format(time.RFC3339), e.FuncName, e.Message, e.Details)
}

// NewCustomError creates a new CustomError with the provided message and details.
func NewCustomError(message, details string) error {
	funcName := getCallerFuncName()
	return &CustomError{
		Timestamp: time.Now(),
		FuncName:  funcName,
		Message:   message,
		Details:   details,
	}
}

// getCallerFuncName returns the name of the function that called the error handling utility.
func getCallerFuncName() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}

	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}

	return fn.Name()
}

// LogError logs the provided error to a file and prints it to the console.
func LogError(err error) {
	logFile, logErr := os.OpenFile("error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if logErr != nil {
		fmt.Printf("Failed to open log file: %v\n", logErr)
		return
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	logger.Println(err)
	fmt.Println(err)
}

// HandleError handles an error by logging it and optionally terminating the program.
func HandleError(err error, terminate bool) {
	if err != nil {
		LogError(err)
		if terminate {
			os.Exit(1)
		}
	}
}

// RecoverFromPanic recovers from a panic, logs the panic message, and continues execution.
func RecoverFromPanic() {
	if r := recover(); r != nil {
		err := fmt.Errorf("panic recovered: %v", r)
		LogError(err)
	}
}

// Example function to demonstrate error handling
func ExampleFunction() {
	defer RecoverFromPanic()

	// Simulate an error
	err := NewCustomError("Example error", "Something went wrong in ExampleFunction")
	HandleError(err, false)
}

func main() {
	ExampleFunction()
}
