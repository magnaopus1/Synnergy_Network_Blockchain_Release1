package syn2369

import (
    "encoding/json"
    "errors"
    "io/ioutil"
    "os"
    "sync"
)

// Storage encapsulates the data storage for the SYN2369 virtual items ledger.
type Storage struct {
    filePath string
    mutex    sync.RWMutex
}

// NewStorage initializes a new Storage instance with the given file path.
func NewStorage(filePath string) *Storage {
    return &Storage{
        filePath: filePath,
    }
}

// LoadItems loads items from a JSON file into the ledger.
func (s *Storage) LoadItems(ledger *ItemLedger) error {
    s.mutex.RLock()
    defer s.mutex.RUnlock()

    file, err := os.Open(s.filePath)
    if err != nil {
        return errors.New("unable to open the storage file")
    }
    defer file.Close()

    bytes, err := ioutil.ReadAll(file)
    if err != nil {
        return errors.New("unable to read the storage file")
    }

    var items map[string]VirtualItem
    if err = json.Unmarshal(bytes, &items); err != nil {
        return errors.New("unable to unmarshal items from the storage file")
    }

    ledger.Items = items
    return nil
}

// SaveItems writes the current state of the ledger to a JSON file.
func (s *Storage) SaveItems(ledger *ItemLedger) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    file, err := os.Create(s.filePath)
    if err != nil {
        return errors.New("unable to create the storage file")
    }
    defer file.Close()

    bytes, err := json.Marshal(ledger.Items)
    if err != nil {
        return errors.New("unable to marshal items into JSON")
    }

    if _, err = file.Write(bytes); err != nil {
        return errors.New("unable to write the storage file")
    }

    return nil
}
