package utils

import (
    "log"
    "os"
    "fmt"
    "io"
    "time"
)

// LogLevel defines the severity of the log message.
type LogLevel int

const (
    DEBUG LogLevel = iota
    INFO
    WARNING
    ERROR
    FATAL
)

// Logger represents a logging instance with severity levels.
type Logger struct {
    *log.Logger
    level LogLevel
}

// NewLogger creates a new logger instance.
// If logFile is not empty, logs will also be written to the specified file.
func NewLogger(logFile string, level LogLevel) *Logger {
    logger := log.New(os.Stdout, "", log.LstdFlags | log.Lmsgprefix)
    if logFile != "" {
        file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
        if err != nil {
            log.Fatalf("Failed to open log file: %s, error: %v", logFile, err)
        }
        logger.SetOutput(io.MultiWriter(os.Stdout, file))
    }
    return &Logger{Logger: logger, level: level}
}

// Debug logs a debug message with the DEBUG prefix.
func (l *Logger) Debug(format string, v ...interface{}) {
    if l.level <= DEBUG {
        l.output("DEBUG", format, v...)
    }
}

// Info logs an informational message with the INFO prefix.
func (l *Logger) Info(format string, v ...interface{}) {
    if l.level <= INFO {
        l.output("INFO", format, v...)
    }
}

// Warning logs a warning message with the WARNING prefix.
func (l *Logger) Warning(format string, v ...interface{}) {
    if l.level <= WARNING {
        l.output("WARNING", format, v...)
    }
}

// Error logs an error message with the ERROR prefix.
func (l *Logger) Error(format string, v ...interface{}) {
    if l.level <= ERROR {
        l.output("ERROR", format, v...)
    }
}

// Fatal logs a fatal error message with the FATAL prefix and exits the application.
func (l *Logger) Fatal(format string, v ...interface{}) {
    if l.level <= FATAL {
        l.output("FATAL", format, v...)
        os.Exit(1)
    }
}

// output formats and outputs a log message.
func (l *Logger) output(prefix string, format string, v ...interface{}) {
    l.Printf("%s: %s", prefix, fmt.Sprintf(format, v...))
}

