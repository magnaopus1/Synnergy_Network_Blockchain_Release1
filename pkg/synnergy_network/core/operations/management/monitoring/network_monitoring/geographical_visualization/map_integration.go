package geographical_visualization

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "io"
    "log"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "google.golang.org/grpc"
    "github.com/dgraph-io/badger/v3"
)

const (
    // Secure storage keys
    encryptionKey = "your-32-byte-long-encryption-key-here"
)

// MapData represents the data structure for geographical visualization.
type MapData struct {
    NodeID      string    `json:"node_id"`
    Location    string    `json:"location"`
    Lat         float64   `json:"lat"`
    Lon         float64   `json:"lon"`
    Timestamp   time.Time `json:"timestamp"`
}

// MapIntegration handles the integration of geographical data for network nodes.
type MapIntegration struct {
    db     *badger.DB
    ctx    context.Context
    cancel context.CancelFunc
    conn   *grpc.ClientConn
    client grpcClient
}

var (
    mapDataRequests = promauto.NewCounter(prometheus.CounterOpts{
        Name: "map_data_requests_total",
        Help: "The total number of requests for map data",
    })
    mapDataErrors = promauto.NewCounter(prometheus.CounterOpts{
        Name: "map_data_errors_total",
        Help: "The total number of errors encountered in map data processing",
    })
)

// NewMapIntegration initializes a new MapIntegration instance.
func NewMapIntegration(dbPath string, grpcAddr string) (*MapIntegration, error) {
    db, err := badger.Open(badger.DefaultOptions(dbPath))
    if err != nil {
        return nil, err
    }

    ctx, cancel := context.WithCancel(context.Background())
    conn, err := grpc.Dial(grpcAddr, grpc.WithInsecure())
    if err != nil {
        return nil, err
    }

    client := newGrpcClient(conn)

    return &MapIntegration{
        db:     db,
        ctx:    ctx,
        cancel: cancel,
        conn:   conn,
        client: client,
    }, nil
}

// Encrypt encrypts data using AES.
func Encrypt(data []byte) (string, error) {
    block, err := aes.NewCipher([]byte(encryptionKey))
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES.
func Decrypt(encryptedData string) ([]byte, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher([]byte(encryptionKey))
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// StoreMapData stores encrypted map data in the database.
func (mi *MapIntegration) StoreMapData(data *MapData) error {
    encryptedData, err := Encrypt([]byte(data.Location))
    if err != nil {
        mapDataErrors.Inc()
        return err
    }

    err = mi.db.Update(func(txn *badger.Txn) error {
        return txn.Set([]byte(data.NodeID), []byte(encryptedData))
    })
    if err != nil {
        mapDataErrors.Inc()
        return err
    }

    mapDataRequests.Inc()
    return nil
}

// FetchMapData retrieves and decrypts map data from the database.
func (mi *MapIntegration) FetchMapData(nodeID string) (*MapData, error) {
    var decryptedData []byte

    err := mi.db.View(func(txn *badger.Txn) error {
        item, err := txn.Get([]byte(nodeID))
        if err != nil {
            return err
        }
        return item.Value(func(val []byte) error {
            decryptedData, err = Decrypt(string(val))
            return err
        })
    })
    if err != nil {
        mapDataErrors.Inc()
        return nil, err
    }

    mapDataRequests.Inc()
    return &MapData{
        NodeID:   nodeID,
        Location: string(decryptedData),
    }, nil
}

// Close closes the database and cancels the context.
func (mi *MapIntegration) Close() error {
    mi.cancel()
    if err := mi.conn.Close(); err != nil {
        return err
    }
    return mi.db.Close()
}

// grpcClient represents the client for gRPC communication.
type grpcClient interface {
    SendMapData(ctx context.Context, data *MapData) error
}

// newGrpcClient creates a new gRPC client.
func newGrpcClient(conn *grpc.ClientConn) grpcClient {
    // Implementation of gRPC client initialization goes here.
    return nil
}
