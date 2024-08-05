package utils

import (
	"encoding/json"
)

// Serialize serializes the given object to a JSON string
func Serialize(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Deserialize deserializes the given JSON string to an object
func Deserialize(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}
