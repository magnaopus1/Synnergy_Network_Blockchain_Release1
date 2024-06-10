package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogRotator is responsible for rotating log files to prevent disk space exhaustion
type LogRotator struct {
	mu          sync.Mutex
	logFile     *os.File
	maxSize     int64
	maxBackups  int
	logDir      string
	logFileName string
}

// NewLogRotator initializes a new LogRotator with specified configurations
func NewLogRotator(logDir, logFileName string, maxSize int64, maxBackups int) (*LogRotator, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	logFilePath := filepath.Join(logDir, logFileName)
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	return &LogRotator{
		logFile:     logFile,
		maxSize:     maxSize,
		maxBackups:  maxBackups,
		logDir:      logDir,
		logFileName: logFileName,
	}, nil
}

// WriteLog writes a log entry to the current log file
func (lr *LogRotator) WriteLog(message string) error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	if err := lr.rotateIfNeeded(); err != nil {
		return err
	}

	if _, err := lr.logFile.WriteString(fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), message)); err != nil {
		return fmt.Errorf("failed to write log entry: %v", err)
	}

	return nil
}

// rotateIfNeeded checks if the current log file needs to be rotated based on its size
func (lr *LogRotator) rotateIfNeeded() error {
	stat, err := lr.logFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat log file: %v", err)
	}

	if stat.Size() >= lr.maxSize {
		if err := lr.rotate(); err != nil {
			return err
		}
	}

	return nil
}

// rotate rotates the current log file, renaming it and creating a new log file
func (lr *LogRotator) rotate() error {
	if err := lr.logFile.Close(); err != nil {
		return fmt.Errorf("failed to close log file: %v", err)
	}

	timestamp := time.Now().Format("20060102T150405")
	rotatedLogFileName := fmt.Sprintf("%s.%s", lr.logFileName, timestamp)
	rotatedLogFilePath := filepath.Join(lr.logDir, rotatedLogFileName)

	if err := os.Rename(filepath.Join(lr.logDir, lr.logFileName), rotatedLogFilePath); err != nil {
		return fmt.Errorf("failed to rename log file: %v", err)
	}

	logFile, err := os.OpenFile(filepath.Join(lr.logDir, lr.logFileName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %v", err)
	}
	lr.logFile = logFile

	if err := lr.cleanupOldLogs(); err != nil {
		return fmt.Errorf("failed to clean up old log files: %v", err)
	}

	return nil
}

// cleanupOldLogs removes old log files exceeding the maxBackups limit
func (lr *LogRotator) cleanupOldLogs() error {
	files, err := filepath.Glob(filepath.Join(lr.logDir, fmt.Sprintf("%s.*", lr.logFileName)))
	if err != nil {
		return fmt.Errorf("failed to list rotated log files: %v", err)
	}

	if len(files) <= lr.maxBackups {
		return nil
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i] < files[j]
	})

	for _, file := range files[:len(files)-lr.maxBackups] {
		if err := os.Remove(file); err != nil {
			return fmt.Errorf("failed to remove old log file: %v", err)
		}
	}

	return nil
}

// Close closes the current log file
func (lr *LogRotator) Close() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.logFile.Close()
}

// Example usage
func main() {
	logDir := "./logs"
	logFileName := "synthron.log"
	maxSize := int64(10 * 1024 * 1024) // 10 MB
	maxBackups := 5

	rotator, err := NewLogRotator(logDir, logFileName, maxSize, maxBackups)
	if err != nil {
		log.Fatalf("Failed to initialize LogRotator: %v", err)
	}
	defer rotator.Close()

	for i := 0; i < 100000; i++ {
		if err := rotator.WriteLog(fmt.Sprintf("This is log entry number %d", i)); err != nil {
			log.Fatalf("Failed to write log entry: %v", err)
		}
	}
}
