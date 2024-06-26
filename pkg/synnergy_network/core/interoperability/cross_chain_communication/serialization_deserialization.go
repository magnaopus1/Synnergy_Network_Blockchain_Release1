package crosschain

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
)

// Serializer defines the interface for serialization operations.
type Serializer interface {
	Serialize(data interface{}) ([]byte, error)
	Deserialize(data []byte, v interface{}) error
}

// JSONSerializer uses JSON for serializing and deserializing data.
type JSONSerializer struct{}

// Serialize converts a data structure to JSON bytes.
func (js *JSONSerializer) Serialize(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

// Deserialize converts JSON bytes back into the specified data structure.
func (js *JSONSerializer) Deserialize(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// GOBSerializer uses GOB encoding for serializing and deserializing data.
type GOBSerializer struct{}

// Serialize converts a data structure to GOB bytes.
func (gs *GOBSerializer) Serialize(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Deserialize converts GOB bytes back into the specified data structure.
func (gs *GOBSerializer) Deserialize(data []byte, v interface{}) error {
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(v)
}

// NewSerializer returns a serializer based on the given type.
func NewSerializer(serializerType string) (Serializer, error) {
	switch serializerType {
	case "json":
		return &JSONSerializer{}, nil
	case "gob":
		return &GOBSerializer{}, nil
	default:
		return nil, errors.New("unsupported serializer type")
	}
}

// Example usage
func main() {
	// Choose the serializer type dynamically
	serializer, err := NewSerializer("json")
	if err != nil {
		panic(err)
	}

	// Example data structure
	type BlockData struct {
		Hash      string
		Timestamp int64
		Data      string
	}

	block := BlockData{
		Hash:      "0x12345",
		Timestamp: 1625239896,
		Data:      "block content",
	}

	// Serialize data
	serializedData, err := serializer.Serialize(block)
	if err != nil {
		panic(err)
	}

	// Deserialize data
	var newBlock BlockData
	if err := serializer.Deserialize(serializedData, &newBlock); err != nil {
		panic(err)
	}
}
