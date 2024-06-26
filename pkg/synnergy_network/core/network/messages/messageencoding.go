package messages

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"log"

	"google.golang.org/protobuf/proto"
)

// Message represents the data structure for network messages.
type Message struct {
	Type    string
	Payload interface{}
}

// EncodeJSON serializes the message using JSON encoding.
func EncodeJSON(msg Message) ([]byte, error) {
	return json.Marshal(msg)
}

// DecodeJSON deserializes the JSON-encoded data into a Message.
func DecodeJSON(data []byte) (Message, error) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	return msg, err
}

// EncodeGOB serializes the message using GOB encoding.
func EncodeGOB(msg Message) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(msg)
	return buffer.Bytes(), err
}

// DecodeGOB deserializes the GOB-encoded data into a Message.
func DecodeGOB(data []byte) (Message, error) {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	var msg Message
	err := decoder.Decode(&msg)
	return msg, err
}

// EncodeProtobuf serializes the message using Protocol Buffers.
func EncodeProtobuf(msg proto.Message) ([]byte, error) {
	return proto.Marshal(msg)
}

// DecodeProtobuf deserializes the Protocol Buffers-encoded data into a Message.
func DecodeProtobuf(data []byte, msg proto.Message) error {
	return proto.Unmarshal(data, msg)
}

func main() {
	// Example Usage
	msg := Message{Type: "Transaction", Payload: "Data"}
	jsonData, err := EncodeJSON(msg)
	if err != nil {
		log.Fatalf("JSON Encoding failed: %v", err)
	}
	log.Println("Encoded JSON:", string(jsonData))

	var decodedMsg Message
	err = DecodeJSON(jsonData, &decodedMsg)
	if err != nil {
		log.Fatalf("JSON Decoding failed: %v", err)
	}
	log.Println("Decoded JSON Message:", decodedMsg)

	// Assuming `proto.Message` is properly defined and passed
	// This is a simplistic representation.
	// protobufData, err := EncodeProtobuf(protoMsg)
	// if err != nil {
	//     log.Fatalf("Protobuf Encoding failed: %v", err)
	// }
	// log.Println("Encoded Protobuf:", protobufData)

	// err = DecodeProtobuf(protobufData, protoMsg)
	// if err != nil {
	//     log.Fatalf("Protobuf Decoding failed: %v", err)
	// }
}
