package child_chain

// other code


import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

type ExitRequest struct {
    Address     string
    Amount      int
    Timestamp   string
    ExitHash    string
    Processed   bool
}

var ExitQueue []ExitRequest
var exitQueueMutex sync.Mutex

func requestExit(address string, amount int) (string, error) {
    if amount <= 0 {
        return "", errors.New("amount must be greater than zero")
    }
    
    // Create a timestamp for the exit request
    timestamp := time.Now().String()
    
    // Generate an exit hash
    hash := sha256.New()
    hash.Write([]byte(address + timestamp + fmt.Sprintf("%d", amount)))
    exitHash := hex.EncodeToString(hash.Sum(nil))
    
    // Create an exit request
    exitRequest := ExitRequest{
        Address:   address,
        Amount:    amount,
        Timestamp: timestamp,
        ExitHash:  exitHash,
        Processed: false,
    }

    // Add the exit request to the queue in a thread-safe manner
    exitQueueMutex.Lock()
    ExitQueue = append(ExitQueue, exitRequest)
    exitQueueMutex.Unlock()
    
    fmt.Println("Exit request added:", exitRequest)
    return exitHash, nil
}

func processExitRequests() {
    exitQueueMutex.Lock()
    defer exitQueueMutex.Unlock()

    for i, request := range ExitQueue {
        if !request.Processed {
            // Process the exit request
            fmt.Println("Processing exit request:", request)
            // Add logic to handle the actual exit, such as updating balances
            
            // Mark the request as processed
            ExitQueue[i].Processed = true
        }
    }
}

func verifyExitRequest(exitHash string) (*ExitRequest, error) {
    exitQueueMutex.Lock()
    defer exitQueueMutex.Unlock()

    for _, request := range ExitQueue {
        if request.ExitHash == exitHash {
            if request.Processed {
                return nil, errors.New("exit request has already been processed")
            }
            return &request, nil
        }
    }
    return nil, errors.New("exit request not found")
}

func cancelExitRequest(exitHash string) error {
    exitQueueMutex.Lock()
    defer exitQueueMutex.Unlock()

    for i, request := range ExitQueue {
        if request.ExitHash == exitHash {
            if request.Processed {
                return errors.New("cannot cancel a processed exit request")
            }
            ExitQueue = append(ExitQueue[:i], ExitQueue[i+1:]...)
            fmt.Println("Exit request cancelled:", request)
            return nil
        }
    }
    return errors.New("exit request not found")
}
