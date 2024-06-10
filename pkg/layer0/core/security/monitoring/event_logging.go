package logging

import (
    "time"
    "log"
    "os"

    "golang.org/x/crypto/argon2"
)

type LogLevel int

const (
    DEBUG LogLevel = iota
    INFO
    WARNING
    ERROR
)

type LogEntry struct {
    Time    time.Time
    Level   LogLevel
    Message string
}

func (l LogEntry) String() string {
    return fmt.Sprintf("[%s] [%s] %s", l.Time.Format(time.RFC3339), l.Level, l.Message)
}

type Logger struct {
    Filename string
    File     *os.File
}

func NewLogger(filename string) (*Logger, error) {
    file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }
    return &Logger{
        Filename: filename,
        File:     file,
    }, nil
}

func (l *Logger) Log(level LogLevel, message string) error {
    entry := LogEntry{
        Time:    time.Now(),
        Level:   level,
        Message: message,
    }
    _, err := l.File.WriteString(entry.String() + "\n")
    return err
}

func (l *Logger) Close() error {
    return l.File.Close()
}

func main() {
    logger, err := NewLogger("event.log")
    if err != nil {
        log.Fatal(err)
    }
    defer logger.Close()

    logger.Log(INFO, "This is an info message")
}
