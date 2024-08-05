package serialization_util

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// SerializeToJSON serializes the given data to a JSON byte array
func SerializeToJSON(data interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize to JSON: %v", err)
	}
	return jsonData, nil
}

// DeserializeFromJSON deserializes the given JSON byte array to the specified data structure
func DeserializeFromJSON(jsonData []byte, data interface{}) error {
	err := json.Unmarshal(jsonData, data)
	if err != nil {
		return fmt.Errorf("failed to deserialize from JSON: %v", err)
	}
	return nil
}

// SerializeToGOB serializes the given data to a GOB byte array
func SerializeToGOB(data interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize to GOB: %v", err)
	}
	return buffer.Bytes(), nil
}

// DeserializeFromGOB deserializes the given GOB byte array to the specified data structure
func DeserializeFromGOB(gobData []byte, data interface{}) error {
	buffer := bytes.NewBuffer(gobData)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(data)
	if err != nil {
		return fmt.Errorf("failed to deserialize from GOB: %v", err)
	}
	return nil
}

// SaveToFile saves the given data to the specified file path in the specified format (JSON or GOB)
func SaveToFile(filePath string, data interface{}, format string) error {
	var serializedData []byte
	var err error

	switch format {
	case "json":
		serializedData, err = SerializeToJSON(data)
	case "gob":
		serializedData, err = SerializeToGOB(data)
	default:
		return fmt.Errorf("unsupported serialization format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to serialize data: %v", err)
	}

	err = os.WriteFile(filePath, serializedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to save data to file: %v", err)
	}

	return nil
}

// LoadFromFile loads the data from the specified file path into the specified data structure using the specified format (JSON or GOB)
func LoadFromFile(filePath string, data interface{}, format string) error {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read data from file: %v", err)
	}

	switch format {
	case "json":
		err = DeserializeFromJSON(fileData, data)
	case "gob":
		err = DeserializeFromGOB(fileData, data)
	default:
		return fmt.Errorf("unsupported deserialization format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to deserialize data: %v", err)
	}

	return nil
}

// LogSerialization logs the serialized data for debugging purposes
func LogSerialization(data interface{}, format string) {
	var serializedData []byte
	var err error

	switch format {
	case "json":
		serializedData, err = SerializeToJSON(data)
	case "gob":
		serializedData, err = SerializeToGOB(data)
	default:
		log.Printf("Unsupported serialization format: %s", format)
		return
	}

	if err != nil {
		log.Printf("Failed to serialize data: %v", err)
		return
	}

	log.Printf("Serialized Data (%s): %s", format, string(serializedData))
}

