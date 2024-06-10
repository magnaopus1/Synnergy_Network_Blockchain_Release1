package indexing

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"synthron_blockchain/pkg/layer0/core/database"
)

// FilterManager manages the application of filters to blockchain data queries
type FilterManager struct {
	db database.Database // Interface to the blockchain database
}

// NewFilterManager initializes a new FilterManager
func NewFilterManager(db database.Database) *FilterManager {
	return &FilterManager{db: db}
}

// ApplyFilters applies given filters to the data retrieved from the blockchain
func (fm *FilterManager) ApplyFilters(ctx context.Context, filters Filters) ([]byte, error) {
	rawData, err := fm.db.QueryData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query data from the database: %w", err)
	}

	filteredData := make([]map[string]interface{}, 0)
	for _, data := range rawData {
		var record map[string]interface{}
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal data: %w", err)
		}

		if fm.matchFilters(record, filters) {
			filteredData = append(filteredData, record)
		}
	}

	result, err := json.Marshal(filteredData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal filtered data: %w", err)
	}

	return result, nil
}

// matchFilters checks if a single data record matches the provided filters
func (fm *FilterManager) matchFilters(data map[string]interface{}, filters Filters) bool {
	for key, value := range filters {
		dataValue, exists := data[key]
		if !exists {
			continue
		}

		match := false
		switch v := value.(type) {
		case string:
			match = dataValue == v
		case regexp.Regexp:
			match = v.MatchString(dataValue.(string))
		case func(interface{}) bool:
			match = v(dataValue)
		default:
			fmt.Printf("Unsupported filter type for key %s\n", key)
		}

		if !match {
			return false
		}
	}
	return true
}

// Filters defines a map of filter keys to values, which can include regular expressions or custom functions
type Filters map[string]interface{}

func main() {
	db := database.NewBlockchainDatabase() // Placeholder for actual database initialization
	filterManager := NewFilterSpinner(db)

	// Example of dynamic filtering with regex and custom function
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filters := Filters{
		"transactionType": "payment",
		"amount":          regexp.MustCompile(`^[\d]+\.[\d]{2}$`), // Regex for matching decimal amounts
		"timestamp": func(v interface{}) bool {
			t, ok := v.(time.Time)
			return ok && t.After(time.Now().Add(-24*time.Hour)) // Filter for transactions in the last 24 hours
		},
	}

	filteredData, err := filterManager.ApplyFilters(ctx, filters)
	if err != nil {
		fmt.Println("Error applying filters:", err)
		return
	}

	fmt.Println("Filtered data:", string(filteredData))
}
