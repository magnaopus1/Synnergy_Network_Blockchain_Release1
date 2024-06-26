package utils

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// Logger is a custom logger with different log levels.
type Logger struct {
	mu       sync.Mutex
	level    LogLevel
	file     *os.File
	logger   *log.Logger
}

// LogLevel defines the severity of the log message.
type LogLevel int

const (
	// DEBUG level for detailed information.
	DEBUG LogLevel = iota
	// INFO level for general information.
	INFO
	// WARN level for potentially harmful situations.
	WARN
	// ERROR level for error events.
	ERROR
	// FATAL level for severe error events.
	FATAL
)

// NewLogger creates a new Logger instance.
func NewLogger(level LogLevel, logFile string) (*Logger, error) {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	return &Logger{
		level:  level,
		file:   file,
		logger: log.New(file, "", log.Ldate|log.Ltime|log.Lshortfile),
	}, nil
}

// SetLogLevel sets the log level.
func (l *Logger) SetLogLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Close closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// logMessage logs a message with the given log level.
func (l *Logger) logMessage(level LogLevel, format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level >= l.level {
		msg := fmt.Sprintf(format, v...)
		switch level {
		case DEBUG:
			l.logger.Printf("DEBUG: %s", msg)
		case INFO:
			l.logger.Printf("INFO: %s", msg)
		case WARN:
			l.logger.Printf("WARN: %s", msg)
		case ERROR:
			l.logger.Printf("ERROR: %s", msg)
		case FATAL:
			l.logger.Printf("FATAL: %s", msg)
			os.Exit(1)
		}
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(format string, v ...interface{}) {
	l.logMessage(DEBUG, format, v...)
}

// Info logs an info message.
func (l *Logger) Info(format string, v ...interface{}) {
	l.logMessage(INFO, format, v...)
}

// Warn logs a warning message.
func (l *Logger) Warn(format string, v ...interface{}) {
	l.logMessage(WARN, format, v...)
}

// Error logs an error message.
func (l *Logger) Error(format string, v ...interface{}) {
	l.logMessage(ERROR, format, v...)
}

// Fatal logs a fatal error message and exits.
func (l *Logger) Fatal(format string, v ...interface{}) {
	l.logMessage(FATAL, format, v...)
}

// StdLogger returns a standard logger.
func (l *Logger) StdLogger() *log.Logger {
	return l.logger
}
