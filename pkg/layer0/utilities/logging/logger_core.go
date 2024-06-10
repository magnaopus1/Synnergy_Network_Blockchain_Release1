package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel defines the level of logging
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// LoggerCore is the core logging structure for the Synthron blockchain
type LoggerCore struct {
	mu        sync.Mutex
	logFile   *os.File
	logLevel  LogLevel
	rotator   *LogRotator
	logDir    string
	logFormat string
}

// NewLoggerCore initializes a new LoggerCore instance
func NewLoggerCore(logDir, logFileName string, maxSize int64, maxBackups int, logLevel LogLevel, logFormat string) (*LoggerCore, error) {
	rotator, err := NewLogRotator(logDir, logFileName, maxSize, maxBackups)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LogRotator: %v", err)
	}

	return &LoggerCore{
		logFile:   rotator.logFile,
		logLevel:  logLevel,
		rotator:   rotator,
		logDir:    logDir,
		logFormat: logFormat,
	}, nil
}

// Log writes a log message with the specified level
func (lc *LoggerCore) Log(level LogLevel, message string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if level < lc.logLevel {
		return nil
	}

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf(lc.logFormat, timestamp, levelToString(level), message)

	if err := lc.rotator.WriteLog(logEntry); err != nil {
		return fmt.Errorf("failed to write log entry: %v", err)
	}

	return nil
}

// Debug logs a message at the DEBUG level
func (lc *LoggerCore) Debug(message string) error {
	return lc.Log(DEBUG, message)
}

// Info logs a message at the INFO level
func (lc *LoggerCore) Info(message string) error {
	return lc.Log(INFO, message)
}

// Warn logs a message at the WARN level
func (lc *LoggerCore) Warn(message string) error {
	return lc.Log(WARN, message)
}

// Error logs a message at the ERROR level
func (lc *LoggerCore) Error(message string) error {
	return lc.Log(ERROR, message)
}

// Fatal logs a message at the FATAL level
func (lc *LoggerCore) Fatal(message string) error {
	return lc.Log(FATAL, message)
}

// levelToString converts a LogLevel to its string representation
func levelToString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Rotate logs manually forces a log rotation
func (lc *LoggerCore) Rotate() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	return lc.rotator.rotate()
}

// Close closes the LoggerCore instance
func (lc *LoggerCore) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.rotator.Close()
}

// Example usage
func main() {
	logDir := "./logs"
	logFileName := "synthron.log"
	maxSize := int64(10 * 1024 * 1024) // 10 MB
	maxBackups := 5
	logLevel := INFO
	logFormat := "[%s] [%s] %s\n" // timestamp, level, message

	logger, err := NewLoggerCore(logDir, logFileName, maxSize, maxBackups, logLevel, logFormat)
	if err != nil {
		fmt.Printf("Failed to initialize LoggerCore: %v\n", err)
		return
	}
	defer logger.Close()

	logger.Info("This is an info message")
	logger.Debug("This is a debug message")
	logger.Warn("This is a warning message")
	logger.Error("This is an error message")
	logger.Fatal("This is a fatal message")

	// Manually rotate logs
	if err := logger.Rotate(); err != nil {
		fmt.Printf("Failed to rotate logs: %v\n", err)
	}
}
