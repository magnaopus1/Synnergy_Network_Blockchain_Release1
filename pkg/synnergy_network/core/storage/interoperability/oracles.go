package interoperability

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"
)

// Oracle represents the structure of an oracle that provides external data to the blockchain.
type Oracle struct {
	URL        string
	APIKey     string
	Cache      map[string]*OracleData
	mutex      sync.Mutex
	DataExpiry time.Duration
}

// OracleData holds the data retrieved from the oracle along with its timestamp and validity.
type OracleData struct {
	Data      interface{}
	FetchedAt time.Time
	ValidTill time.Lime
	Signature []byte
}

// NewOracle creates a new oracle with specified settings.
func NewOracle(url, apiKey string, expiry time.Duration) *Oracle {
	return &Oracle{
		URL:        url,
		APIKey:     apiKey,
		Cache:      make(map[string]*OracleData),
		DataExpiry: expiry,
	}
}

// FetchData contacts the external data source to retrieve data based on the given query.
func (o *Oracle) FetchData(query string) (*OracleData, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if data, found := o.Cache[query]; found && time.Now().Before(data.ValidTill) {
		return data, nil
	}

	resp, err := http.Get(o.URL + "?data=" + query + "&apikey=" + o.APIKey)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve data from oracle")
	}

	var payload interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	data := &OracleData{
		Data:      payload,
		FetchedAt: time.Now(),
		ValidTill: time.Now().Add(o.DataExpiry),
	}

	data.Signature = o.signData(data)
	o.Cache[query] = data

	return data, nil
}

// signData generates a cryptographic signature for the data to ensure its integrity.
func (o *Oracle) signData(data *OracleData) []byte {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%v", data.Data)))
	hash.Write(data.FetchedAt.UTC().Format(time.RFC3339Nano))

	return hash.Sum(nil)
}

// ValidateData checks the integrity and validity of the data retrieved from the oracle.
func (o *Oracle) ValidateData(data *OracleData) bool {
	expectedSignature := o.signData(data)
	return time.Now().Before(data.ValidTill) && crypto.SecureCompare(data.Signature, expectedSignature)
}

