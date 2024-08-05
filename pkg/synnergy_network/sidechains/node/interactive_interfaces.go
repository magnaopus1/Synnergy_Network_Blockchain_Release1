// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including interactive interfaces for real-world use.
package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// Node represents a blockchain node with interactive interface capabilities.
type Node struct {
	ID             string
	Address        string
	PrivateKey     string
	PublicKey      string
	Peers          map[string]*Peer
	mutex          sync.Mutex
	Configuration  Configuration
	InteractiveAPI *InteractiveAPI
}

// Peer represents a peer node in the network.
type Peer struct {
	ID      string
	Address string
	Load    int
}

// Configuration holds the configuration data for a node.
type Configuration struct {
	MaxLoad           int
	ScalingThreshold  int
	ScalingFactor     int
	ScalingCooldown   int
}

// InteractiveAPI represents the interactive API for node interactions.
type InteractiveAPI struct {
	Node   *Node
	Server *http.Server
}

// NewNode creates a new Node instance with specified parameters.
func NewNode(id, address, privateKey, publicKey string) *Node {
	return &Node{
		ID:            id,
		Address:       address,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		Peers:         make(map[string]*Peer),
		Configuration: Configuration{},
		InteractiveAPI: &InteractiveAPI{
			Node: nil,
		},
	}
}

// StartAPI starts the interactive API server for the node.
func (api *InteractiveAPI) StartAPI(port int) error {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/info", api.InfoHandler)
	mux.HandleFunc("/peers", api.PeersHandler)
	mux.HandleFunc("/addPeer", api.AddPeerHandler)
	mux.HandleFunc("/removePeer", api.RemovePeerHandler)

	api.Server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if err := api.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Error starting API server: %v\n", err)
		}
	}()
	fmt.Printf("Interactive API server started on port %d\n", port)
	return nil
}

// StopAPI stops the interactive API server for the node.
func (api *InteractiveAPI) StopAPI() error {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	if api.Server != nil {
		if err := api.Server.Close(); err != nil {
			return err
		}
		fmt.Println("Interactive API server stopped")
	}
	return nil
}

// InfoHandler handles requests for node information.
func (api *InteractiveAPI) InfoHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	info := map[string]interface{}{
		"ID":        api.Node.ID,
		"Address":   api.Node.Address,
		"PublicKey": api.Node.PublicKey,
		"Peers":     api.Node.Peers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// PeersHandler handles requests for the list of peers.
func (api *InteractiveAPI) PeersHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	peers := make([]*Peer, 0, len(api.Node.Peers))
	for _, peer := range api.Node.Peers {
		peers = append(peers, peer)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

// AddPeerHandler handles requests to add a new peer.
func (api *InteractiveAPI) AddPeerHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	var peer Peer
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, exists := api.Node.Peers[peer.ID]; exists {
		http.Error(w, "Peer already exists", http.StatusConflict)
		return
	}

	api.Node.Peers[peer.ID] = &peer
	w.WriteHeader(http.StatusCreated)
}

// RemovePeerHandler handles requests to remove a peer.
func (api *InteractiveAPI) RemovePeerHandler(w http.ResponseWriter, r *http.Request) {
	api.Node.mutex.Lock()
	defer api.Node.mutex.Unlock()

	var peer Peer
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, exists := api.Node.Peers[peer.ID]; !exists {
		http.Error(w, "Peer not found", http.StatusNotFound)
		return
	}

	delete(api.Node.Peers, peer.ID)
	w.WriteHeader(http.StatusOK)
}

// GenerateKeys generates a public-private key pair for the node.
func (n *Node) GenerateKeys(password string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	privateKey, publicKey, err := generateKeyPair(password)
	if err != nil {
		return err
	}

	n.PrivateKey = privateKey
	n.PublicKey = publicKey
	fmt.Printf("Generated keys for node %s\n", n.ID)
	return nil
}

// generateKeyPair generates a public-private key pair using Scrypt for key derivation.
func generateKeyPair(password string) (string, string, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", "", err
	}

	privateKeyBytes, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	privateKey := hex.EncodeToString(privateKeyBytes)
	hash := sha256.New()
	hash.Write(privateKeyBytes)
	publicKey := hex.EncodeToString(hash.Sum(nil))

	return privateKey, publicKey, nil
}

// Example usage:
// func main() {
// 	node := NewNode("node-1", "address-1", "", "")
// 	node.GenerateKeys("strongpassword")
// 	node.InteractiveAPI.StartAPI(8080)
// 	defer node.InteractiveAPI.StopAPI()
// }
