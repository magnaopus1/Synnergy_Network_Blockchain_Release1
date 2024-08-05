package utils

import (
	"log"
	"os"
)

// CheckError logs the error and terminates the program if an error occurred
func CheckError(err error) {
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

// LogError logs the error to the console
func LogError(err error) {
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
}

// LogToFile logs the error to a specified file
func LogToFile(err error, filePath string) {
	if err != nil {
		file, fileErr := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if fileErr != nil {
			log.Printf("Error opening log file: %v\n", fileErr)
			return
		}
		defer file.Close()

		logger := log.New(file, "", log.LstdFlags)
		logger.Printf("Error: %v\n", err)
	}
}
