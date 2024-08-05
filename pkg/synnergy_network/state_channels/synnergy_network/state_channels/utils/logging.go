package utils

import (
	"log"
	"os"
)

// InitializeLogging sets up logging to a file
func InitializeLogging(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}

	log.SetOutput(file)
	return nil
}

// LogInfo logs informational messages
func LogInfo(message string) {
	log.Printf("INFO: %s\n", message)
}

// LogWarning logs warning messages
func LogWarning(message string) {
	log.Printf("WARNING: %s\n", message)
}

// LogError logs error messages
func LogError(message string) {
	log.Printf("ERROR: %s\n", message)
}
