package maintenance_integration

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io"
    "log"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/scrypt"
)

// Task represents a maintenance task that can be automated
type Task struct {
    ID          string
    Name        string
    Description string
    Frequency   time.Duration
    LastRun     time.Time
    Command     func() error
}

// TaskScheduler schedules and runs maintenance tasks
type TaskScheduler struct {
    tasks      []Task
    stopChan   chan bool
    isRunning  bool
    context    context.Context
    cancelFunc context.CancelFunc
}

// NewTaskScheduler creates a new TaskScheduler
func NewTaskScheduler() *TaskScheduler {
    ctx, cancel := context.WithCancel(context.Background())
    return &TaskScheduler{
        tasks:      []Task{},
        stopChan:   make(chan bool),
        context:    ctx,
        cancelFunc: cancel,
    }
}

// AddTask adds a new task to the scheduler
func (s *TaskScheduler) AddTask(name, description string, frequency time.Duration, command func() error) {
    task := Task{
        ID:          uuid.New().String(),
        Name:        name,
        Description: description,
        Frequency:   frequency,
        LastRun:     time.Now(),
        Command:     command,
    }
    s.tasks = append(s.tasks, task)
}

// Start starts the task scheduler
func (s *TaskScheduler) Start() {
    s.isRunning = true
    go func() {
        ticker := time.NewTicker(time.Minute)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                s.runDueTasks()
            case <-s.stopChan:
                return
            case <-s.context.Done():
                return
            }
        }
    }()
}

// Stop stops the task scheduler
func (s *TaskScheduler) Stop() {
    if s.isRunning {
        s.cancelFunc()
        s.stopChan <- true
        s.isRunning = false
    }
}

// runDueTasks runs tasks that are due
func (s *TaskScheduler) runDueTasks() {
    for _, task := range s.tasks {
        if time.Since(task.LastRun) >= task.Frequency {
            go s.runTask(task)
        }
    }
}

// runTask runs a specific task
func (s *TaskScheduler) runTask(task Task) {
    err := task.Command()
    if err != nil {
        log.Printf("Task %s failed: %v", task.Name, err)
    } else {
        log.Printf("Task %s completed successfully", task.Name)
        task.LastRun = time.Now()
    }
}

// SecureData represents encrypted data
type SecureData struct {
    Data string
    Salt string
}

// EncryptData encrypts the given data using AES
func EncryptData(data, passphrase string) (SecureData, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return SecureData{}, err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return SecureData{}, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return SecureData{}, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return SecureData{}, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return SecureData{}, err
    }

    encryptedData := gcm.Seal(nonce, nonce, []byte(data), nil)
    return SecureData{
        Data: base64.StdEncoding.EncodeToString(encryptedData),
        Salt: base64.StdEncoding.EncodeToString(salt),
    }, nil
}

// DecryptData decrypts the given data using AES
func DecryptData(encryptedData, passphrase, saltStr string) (string, error) {
    salt, err := base64.StdEncoding.DecodeString(saltStr)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedBytes) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := encryptedBytes[:nonceSize], encryptedBytes[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(decryptedData), nil
}
