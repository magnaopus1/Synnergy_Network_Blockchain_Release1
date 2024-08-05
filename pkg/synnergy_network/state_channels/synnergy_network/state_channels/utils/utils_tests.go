package utils

import (
	"testing"
)

func TestEncryption(t *testing.T) {
	password := []byte("securepassword")
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Error generating salt: %v", err)
	}
	key := GenerateKey(password, salt)

	plaintext := "This is a secret message."
	ciphertext, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("Error encrypting data: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Error decrypting data: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Expected %s but got %s", plaintext, string(decrypted))
	}
}

func TestSerialization(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	obj := TestStruct{Name: "Test", Value: 42}
	serialized, err := Serialize(obj)
	if err != nil {
		t.Fatalf("Error serializing object: %v", err)
	}

	var deserialized TestStruct
	err = Deserialize(serialized, &deserialized)
	if err != nil {
		t.Fatalf("Error deserializing object: %v", err)
	}

	if deserialized != obj {
		t.Errorf("Expected %v but got %v", obj, deserialized)
	}
}

func TestLogging(t *testing.T) {
	err := InitializeLogging("test.log")
	if err != nil {
		t.Fatalf("Error initializing logging: %v", err)
	}

	LogInfo("This is an info message")
	LogWarning("This is a warning message")
	LogError("This is an error message")
}
