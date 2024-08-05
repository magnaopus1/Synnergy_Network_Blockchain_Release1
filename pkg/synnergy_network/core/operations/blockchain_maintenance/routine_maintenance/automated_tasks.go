package routine_maintenance

import (
    "time"
    "sync"
    "log"
    "errors"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "golang.org/x/crypto/scrypt"
    "encoding/hex"
)

// Task defines a maintenance task
type Task struct {
    ID          string
    Description string
    Interval    time.Duration
    LastRun     time.Time
    NextRun     time.Time
    TaskFunc    func() error
}

// MaintenanceTaskManager manages routine maintenance tasks
type MaintenanceTaskManager struct {
    tasks        map[string]*Task
    mutex        sync.Mutex
    taskTicker   *time.Ticker
    stopChan     chan bool
    encryptionKey []byte
}

// NewMaintenanceTaskManager creates a new MaintenanceTaskManager
func NewMaintenanceTaskManager(encryptionKey []byte) *MaintenanceTaskManager {
    return &MaintenanceTaskManager{
        tasks:        make(map[string]*Task),
        taskTicker:   time.NewTicker(1 * time.Minute),
        stopChan:     make(chan bool),
        encryptionKey: encryptionKey,
    }
}

// AddTask adds a new maintenance task
func (mtm *MaintenanceTaskManager) AddTask(id, description string, interval time.Duration, taskFunc func() error) {
    mtm.mutex.Lock()
    defer mtm.mutex.Unlock()

    mtm.tasks[id] = &Task{
        ID:          id,
        Description: description,
        Interval:    interval,
        LastRun:     time.Now(),
        NextRun:     time.Now().Add(interval),
        TaskFunc:    taskFunc,
    }
}

// RemoveTask removes a maintenance task
func (mtm *MaintenanceTaskManager) RemoveTask(id string) {
    mtm.mutex.Lock()
    defer mtm.mutex.Unlock()

    delete(mtm.tasks, id)
}

// Start starts the task manager
func (mtm *MaintenanceTaskManager) Start() {
    go func() {
        for {
            select {
            case <-mtm.taskTicker.C:
                mtm.runTasks()
            case <-mtm.stopChan:
                return
            }
        }
    }()
}

// Stop stops the task manager
func (mtm *MaintenanceTaskManager) Stop() {
    mtm.stopChan <- true
    mtm.taskTicker.Stop()
}

// runTasks runs the scheduled tasks
func (mtm *MaintenanceTaskManager) runTasks() {
    mtm.mutex.Lock()
    defer mtm.mutex.Unlock()

    for _, task := range mtm.tasks {
        if time.Now().After(task.NextRun) {
            go func(task *Task) {
                if err := task.TaskFunc(); err != nil {
                    log.Printf("Error running task %s: %v", task.ID, err)
                } else {
                    task.LastRun = time.Now()
                    task.NextRun = time.Now().Add(task.Interval)
                }
            }(task)
        }
    }
}

// EncryptTask encrypts a task's description
func (mtm *MaintenanceTaskManager) EncryptTask(taskID string) error {
    mtm.mutex.Lock()
    defer mtm.mutex.Unlock()

    task, exists := mtm.tasks[taskID]
    if !exists {
        return errors.New("task not found")
    }

    block, err := aes.NewCipher(mtm.encryptionKey)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(task.Description), nil)
    task.Description = hex.EncodeToString(ciphertext)

    return nil
}

// DecryptTask decrypts a task's description
func (mtm *MaintenanceTaskManager) DecryptTask(taskID string) error {
    mtm.mutex.Lock()
    defer mtm.mutex.Unlock()

    task, exists := mtm.tasks[taskID]
    if !exists {
        return errors.New("task not found")
    }

    ciphertext, err := hex.DecodeString(task.Description)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(mtm.encryptionKey)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    task.Description = string(plaintext)
    return nil
}

// generateEncryptionKey generates an encryption key using scrypt
func generateEncryptionKey(passphrase, salt string) ([]byte, error) {
    return scrypt.Key([]byte(passphrase), []byte(salt), 16384, 8, 1, 32)
}

// InitializeMaintenanceTaskManager initializes the task manager with encryption key
func InitializeMaintenanceTaskManager(passphrase, salt string) (*MaintenanceTaskManager, error) {
    key, err := generateEncryptionKey(passphrase, salt)
    if err != nil {
        return nil, err
    }

    return NewMaintenanceTaskManager(key), nil
}
