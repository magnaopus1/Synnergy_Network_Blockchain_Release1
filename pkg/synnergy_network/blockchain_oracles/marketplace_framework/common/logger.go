package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// LogLevel defines the log levels
type LogLevel int

const (
	// LogLevelDebug defines debug level logging
	LogLevelDebug LogLevel = iota
	// LogLevelInfo defines info level logging
	LogLevelInfo
	// LogLevelWarn defines warning level logging
	LogLevelWarn
	// LogLevelError defines error level logging
	LogLevelError
	// LogLevelFatal defines fatal level logging
	LogLevelFatal
)

var (
	logger     *log.Logger
	logLevel   LogLevel
	logFile    *os.File
	once       sync.Once
	logFilePath string
)

// InitLogger initializes the logger
func InitLogger(level string, filePath string) {
	once.Do(func() {
		setLogLevel(level)
		setLogFilePath(filePath)

		var err error
		logFile, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %s, error: %v", logFilePath, err)
		}

		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger = log.New(multiWriter, "", log.Ldate|log.Ltime|log.Lshortfile)
	})
}

// setLogLevel sets the logging level
func setLogLevel(level string) {
	switch level {
	case "DEBUG":
		logLevel = LogLevelDebug
	case "INFO":
		logLevel = LogLevelInfo
	case "WARN":
		logLevel = LogLevelWarn
	case "ERROR":
		logLevel = LogLevelError
	case "FATAL":
		logLevel = LogLevelFatal
	default:
		logLevel = LogLevelInfo
	}
}

// setLogFilePath sets the logging file path
func setLogFilePath(filePath string) {
	if filePath == "" {
		logFilePath = "logs/synnergy_network.log"
	} else {
		logFilePath = filePath
	}
}

// Debug logs a debug message
func Debug(v ...interface{}) {
	if logLevel <= LogLevelDebug {
		logger.SetPrefix("DEBUG: ")
		logger.Output(2, fmt.Sprintln(v...))
	}
}

// Info logs an info message
func Info(v ...interface{}) {
	if logLevel <= LogLevelInfo {
		logger.SetPrefix("INFO: ")
		logger.Output(2, fmt.Sprintln(v...))
	}
}

// Warn logs a warning message
func Warn(v ...interface{}) {
	if logLevel <= LogLevelWarn {
		logger.SetPrefix("WARN: ")
		logger.Output(2, fmt.Sprintln(v...))
	}
}

// Error logs an error message
func Error(v ...interface{}) {
	if logLevel <= LogLevelError {
		logger.SetPrefix("ERROR: ")
		logger.Output(2, fmt.Sprintln(v...))
	}
}

// Fatal logs a fatal message and exits the application
func Fatal(v ...interface{}) {
	if logLevel <= LogLevelFatal {
		logger.SetPrefix("FATAL: ")
		logger.Output(2, fmt.Sprintln(v...))
		os.Exit(1)
	}
}

// CloseLogger closes the log file
func CloseLogger() {
	if logFile != nil {
		logFile.Close()
	}
}
