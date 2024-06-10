package partitioning

import (
	"log"
	"sync"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// Data represents the unit of blockchain data, which can be a transaction or any other data structure.
type Data struct {
	ID       string
	Content  []byte
}

// Partition represents a segment of data grouped under a single criterion.
type Partition struct {
	DataItems []Data
	Lock      sync.RWMutex
}

// Rebalancer manages dynamic partitioning and rebalancing of data across the blockchain.
type Rebalancer struct {
	Partitions map[string]*Partition
	Lock       sync.Mutex
	encryptionKey []byte // AES encryption key for data integrity and security
}

// NewRebalancer initializes a Rebalancer instance with an encryption key.
func NewRebalancer(key string) (*Rebalancer, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes long")
	}

	return &Rebalancer{
		Partitions: make(map[string]*Partition),
		encryptionKey: []byte(key),
	}, nil
}

// EncryptData encrypts data using AES-256.
func (r *Rebalancer) EncryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(r.encryptionKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES-256.
func (r *Rebalancer) DecryptData(cryptoText string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(r.encryptionKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// AddData assigns data to a partition and encrypts it.
func (r *Rebalancer) AddData(partitionKey string, data Data) error {
	r.Lock.Lock()
	defer r.Lock.Unlock()

	encryptedData, err := r.EncryptData(data.Content)
	if err != nil {
		return err
	}
	data.Content = []byte(encryptedData)

	partition, exists := r.Partitions[partitionKey]
	if !exists {
		partition = &Partition{}
		r.Partitions[partitionKey] = partition
	}

	partition.Lock.Lock()
	defer partition.Lock.Unlock()
	partition.DataItems = append(partition.DataItems, data)
	return nil
}

// Rebalance redistributes data among partitions to optimize access and load.
func (r *Rebalancer) Rebalance() {
	r.Lock.Lock()
	defer r.Lock.Unlock()
	// Example logic: Check each partition's load and redistribute
	log.Println("Rebalancing data across partitions...")
	// More sophisticated rebalancing logic can be implemented here
}

func main() {
	key := "your-secret-key-here-32-bytes-long"
	r, err := NewRebalancer(key)
	if err != nil {
		log.Fatal(err)
	}

	// Example usage
	data := Data{ID: "data1", Content: []byte("blockchain transaction data")}
	if err := r.AddData("partition1", data); err != nil {
		log.Println("Failed to add data:", err)
		return
	}

	// Simulate periodic rebalancing
	go func() {
		for {
			r.Rebalance()
			time.Sleep(10 * time.Minute)
		}
	}()

	// Further implementation as needed
}
