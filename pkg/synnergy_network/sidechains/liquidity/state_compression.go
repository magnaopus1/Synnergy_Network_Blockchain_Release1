package liquidity

import (
    "bytes"
    "crypto/sha256"
    "encoding/gob"
    "errors"
    "log"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/klauspost/compress/zstd"
    "golang.org/x/crypto/scrypt"
)

// StateCompression represents the structure for state compression
type StateCompression struct {
    StateID      string
    Data         []byte
    Compressed   []byte
    Timestamp    time.Time
    mutex        sync.Mutex
}

// StateManager manages state compression and decompression
type StateManager struct {
    states map[string]*StateCompression
    mutex  sync.Mutex
}

// NewStateManager creates a new StateManager
func NewStateManager() *StateManager {
    return &StateManager{
        states: make(map[string]*StateCompression),
    }
}

// CompressState compresses the given state data using Zstd
func (sm *StateManager) CompressState(stateID string, data []byte) ([]byte, error) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    var b bytes.Buffer
    w, err := zstd.NewWriter(&b)
    if err != nil {
        return nil, err
    }
    _, err = w.Write(data)
    if err != nil {
        return nil, err
    }
    w.Close()

    compressedData := b.Bytes()

    sm.states[stateID] = &StateCompression{
        StateID:    stateID,
        Data:       data,
        Compressed: compressedData,
        Timestamp:  time.Now(),
    }

    return compressedData, nil
}

// DecompressState decompresses the given state data using Zstd
func (sm *StateManager) DecompressState(stateID string) ([]byte, error) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    state, exists := sm.states[stateID]
    if !exists {
        return nil, errors.New("state not found")
    }

    r, err := zstd.NewReader(bytes.NewReader(state.Compressed))
    if err != nil {
        return nil, err
    }
    decompressedData, err := io.ReadAll(r)
    if err != nil {
        return nil, err
    }
    r.Close()

    return decompressedData, nil
}

// SaveState saves the state to a persistent storage (for demonstration, using in-memory storage)
func (sm *StateManager) SaveState(stateID string, data []byte) error {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    state, exists := sm.states[stateID]
    if !exists {
        return errors.New("state not found")
    }

    var buf bytes.Buffer
    enc := gob.NewEncoder(&buf)
    err := enc.Encode(state)
    if err != nil {
        return err
    }

    sm.states[stateID].Compressed = buf.Bytes()

    log.Printf("State %s saved successfully", stateID)
    return nil
}

// LoadState loads the state from a persistent storage (for demonstration, using in-memory storage)
func (sm *StateManager) LoadState(stateID string) ([]byte, error) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    state, exists := sm.states[stateID]
    if !exists {
        return nil, errors.New("state not found")
    }

    var buf bytes.Buffer
    buf.Write(state.Compressed)

    dec := gob.NewDecoder(&buf)
    err := dec.Decode(&state)
    if err != nil {
        return nil, err
    }

    sm.states[stateID] = state
    log.Printf("State %s loaded successfully", stateID)
    return state.Data, nil
}

// SecureHash generates a secure hash using Scrypt
func SecureHash(data string, salt []byte) (string, error) {
    hash, err := scrypt.Key([]byte(data), salt, 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(hash), nil
}

// SimulateStateChanges simulates state changes for testing
func (sm *StateManager) SimulateStateChanges() {
    go func() {
        for {
            stateID := uuid.New().String()
            data := []byte("Example state data for " + stateID)
            compressedData, err := sm.CompressState(stateID, data)
            if err != nil {
                log.Printf("Error compressing state %s: %v", stateID, err)
                continue
            }

            log.Printf("Compressed state %s: %x", stateID, compressedData)

            err = sm.SaveState(stateID, compressedData)
            if err != nil {
                log.Printf("Error saving state %s: %v", stateID, err)
                continue
            }

            loadedData, err := sm.LoadState(stateID)
            if err != nil {
                log.Printf("Error loading state %s: %v", stateID, err)
                continue
            }

            decompressedData, err := sm.DecompressState(stateID)
            if err != nil {
                log.Printf("Error decompressing state %s: %v", stateID, err)
                continue
            }

            log.Printf("Decompressed state %s: %s", stateID, string(decompressedData))

            time.Sleep(5 * time.Second)
        }
    }()
}
