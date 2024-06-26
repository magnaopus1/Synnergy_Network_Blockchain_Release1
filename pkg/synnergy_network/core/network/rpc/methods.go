package rpc

import (
	"errors"
	"net/rpc"
	"github.com/synthron_blockchain_final/pkg/layer0/core/transaction"
	"github.com/synthron_blockchain_final/pkg/layer0/core/blockchain"
	"github.com/synthron_blockchain_final/pkg/layer0/core/network/security"
)

// RPCHandler handles incoming RPC requests and processes them.
type RPCHandler struct {
	Blockchain *blockchain.Blockchain
}

// NewRPCHandler initializes a new RPCHandler with a reference to the blockchain.
func NewRPCHandler(blockchain *blockchain.Blockchain) *RPCHandler {
	return &RPCHandler{
		Blockchain: blockchain,
	}
}

// ProcessTransaction takes a transaction from a remote node and processes it.
func (h *RPCHandler) ProcessTransaction(args *transaction.TransactionArgs, reply *transaction.TransactionReply) error {
	// Authentication and security checks
	if !security.ValidateTransaction(args.Transaction) {
		return errors.New("invalid transaction")
	}

	// Process the transaction
	result, err := h.Blockchain.ProcessTransaction(args.Transaction)
	if err != nil {
		return err
	}

	reply.Result = result
	return nil
}

// GetBlock retrieves a block based on the given block hash.
func (h *RPCHandler) GetBlock(args *blockchain.BlockArgs, reply *blockchain.BlockReply) error {
	block, err := h.Blockchain.GetBlock(args.Hash)
	if err != nil {
		return err
	}

	reply.Block = block
	return nil
}

// RegisterRPCMethods registers the methods that the RPC server can expose to clients.
func RegisterRPCMethods(server *rpc.Server, handler *RPCHandler) {
	server.RegisterName("BlockchainRPC", handler)
}

// Here you can add more methods related to blockchain operations like querying block data,
// managing wallets, handling consensus operations, etc., ensuring all methods are secure and performant.
