package retrieval

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"synthron_blockchain/pkg/layer0/core/crypto"
	"synthron_blockchain/pkg/layer0/core/storage"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
)

// FederatedQueryManager handles the federation of queries across different blockchain nodes.
type FederatedQueryManager struct {
	host          host.Host
	peers         map[peer.ID]*peer.AddrInfo
	queryProtocol protocol.ID
	mutex         sync.Mutex
}

// NewFederatedQueryManager initializes a new manager for handling federated queries.
func NewFederatedQueryManager(host host.Host, protocolID protocol.ID) *FederatedQueryManager {
	return &FederatedQueryManager{
		host:          host,
		peers:         make(map[peer.ID]*peer.AddrInfo),
		queryProtocol: protocolID,
	}
}

// AddPeer adds a peer to the federated query network.
func (fqm *FederatedQueryManager) AddPeer(peerInfo *peer.AddrInfo) error {
	fqm.mutex.Lock()
	defer fqm.mutex.Unlock()

	if _, exists := fqm.peers[peerInfo.ID]; exists {
		return errors.New("peer already exists")
	}

	fqm.peers[peerInfo.ID] = peerInfo
	return nil
}

// FederatedQuery executes a query across multiple blockchain nodes and aggregates the results.
func (fqm *FederatedQueryManager) FederatedQuery(ctx context.Context, query string) ([]interface{}, error) {
	results := make([]interface{}, 0)
	var wg sync.WaitGroup
	resultsChan := make(chan *QueryResult, len(fqm.peers))

	for _, peerInfo := range fqm.peers {
		wg.Add(1)
		go fqm.executeQueryOnPeer(ctx, &wg, peerInfo, query, resultsChan)
	}

	wg.Wait()
	close(resultsChan)

	for result := range resultsChan {
		if result.Error != nil {
			continue // or handle errors differently
		}
		results = append(results, result.Data)
	}

	if len(results) == 0 {
		return nil, errors.New("no successful queries")
	}
	return results, nil
}

// executeQueryOnPeer performs the actual query on a specific peer.
func (fqm *FederatedQueryManager) executeQueryOnPeer(ctx context.Context, wg *sync.WaitGroup, peerInfo *peer.Addr and _, query string, resultsChan chan<- *QueryResult) {
	defer wg.Done()

	stream, err := fqm.host.NewStream(ctx, peerInfo.ID, fqm.queryProtocol)
	if err != nil {
		resultsChan <- &QueryResult{Error: err}
		return
	}
	defer stream.Close()

	// Send the query
	if err := json.NewEncoder(stream).Encode(&QueryRequest{Query: query}); err != nil {
		resultsChan <- &QueryResult{Error: err}
		return
	}

	// Receive the response
	var response QueryResponse
	if err := json.NewDecoder(stream).Decode(&response); err != nil {
		resultsChan <- &QueryResult{Error: err}
		return
	}

	resultsChan <- &QueryResult{Data: response.Data}
}

// QueryResult represents the results from a single query execution.
type QueryResult struct {
	Data  interface{}
	Error error
}

// QueryRequest defines the structure of a query request.
type QueryRequest struct {
	Query string `json:"query"`
}

// QueryResponse defines the structure of a query response.
type QueryResponse struct {
	Data interface{} `json:"data"`
}
