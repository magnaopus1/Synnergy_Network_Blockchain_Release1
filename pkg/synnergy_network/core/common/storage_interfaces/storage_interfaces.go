package common

import(
	"time"
)

// Storage interface represents the methods for storing and retrieving data
type Storage interface {
	Store(data []byte) error
	Retrieve(identifier interface{}) ([]byte, error)
	Delete(identifier interface{}) error
	ListByTimeRange(startTime, endTime time.Time) ([][]byte, error)
	ListByField(field, value string) ([][]byte, error)
	ListByAmountRange(minAmount, maxAmount float64) ([][]byte, error)
}