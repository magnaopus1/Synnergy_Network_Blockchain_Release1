package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synthron_blockchain/pkg/layer0/node/lightning_node"
)

// Test initializing the node
func TestInitNode(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")
	assert.NotNil(t, node, "Node should be initialized")
}

// Test starting the node
func TestStartNode(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")
}

// Test stopping the node
func TestStopNode(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}

// Test opening a payment channel
func TestOpenPaymentChannel(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	peer := "peer1.synthron.org:9735"
	capacity := int64(100000) // in satoshis

	channelID, err := node.OpenChannel(peer, capacity)
	assert.NoError(t, err, "Opening a payment channel should not return an error")
	assert.NotEmpty(t, channelID, "Channel ID should not be empty")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}

// Test closing a payment channel
func TestClosePaymentChannel(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	peer := "peer1.synthron.org:9735"
	capacity := int64(100000) // in satoshis

	channelID, err := node.OpenChannel(peer, capacity)
	assert.NoError(t, err, "Opening a payment channel should not return an error")
	assert.NotEmpty(t, channelID, "Channel ID should not be empty")

	err = node.CloseChannel(channelID)
	assert.NoError(t, err, "Closing a payment channel should not return an error")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}

// Test sending a payment
func TestSendPayment(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	peer := "peer1.synthron.org:9735"
	capacity := int64(100000) // in satoshis

	channelID, err := node.OpenChannel(peer, capacity)
	assert.NoError(t, err, "Opening a payment channel should not return an error")
	assert.NotEmpty(t, channelID, "Channel ID should not be empty")

	amount := int64(10000) // in satoshis
	paymentID, err := node.SendPayment(channelID, amount)
	assert.NoError(t, err, "Sending a payment should not return an error")
	assert.NotEmpty(t, paymentID, "Payment ID should not be empty")

	err = node.CloseChannel(channelID)
	assert.NoError(t, err, "Closing a payment channel should not return an error")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}

// Test receiving a payment
func TestReceivePayment(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	peer := "peer1.synthron.org:9735"
	capacity := int64(100000) // in satoshis

	channelID, err := node.OpenChannel(peer, capacity)
	assert.NoError(t, err, "Opening a payment channel should not return an error")
	assert.NotEmpty(t, channelID, "Channel ID should not be empty")

	amount := int64(10000) // in satoshis
	invoiceID, err := node.CreateInvoice(amount)
	assert.NoError(t, err, "Creating an invoice should not return an error")
	assert.NotEmpty(t, invoiceID, "Invoice ID should not be empty")

	err = node.ReceivePayment(invoiceID)
	assert.NoError(t, err, "Receiving a payment should not return an error")

	err = node.CloseChannel(channelID)
	assert.NoError(t, err, "Closing a payment channel should not return an error")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}

// Test querying channel status
func TestQueryChannelStatus(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	peer := "peer1.synthron.org:9735"
	capacity := int64(100000) // in satoshis

	channelID, err := node.OpenChannel(peer, capacity)
	assert.NoError(t, err, "Opening a payment channel should not return an error")
	assert.NotEmpty(t, channelID, "Channel ID should not be empty")

	status, err := node.QueryChannelStatus(channelID)
	assert.NoError(t, err, "Querying channel status should not return an error")
	assert.Equal(t, "open", status, "Channel status should be open")

	err = node.CloseChannel(channelID)
	assert.NoError(t, err, "Closing a payment channel should not return an error")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}

// Test querying node status
func TestQueryNodeStatus(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	status := node.QueryNodeStatus()
	assert.Equal(t, "running", status, "Node status should be running")

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")

	status = node.QueryNodeStatus()
	assert.Equal(t, "stopped", status, "Node status should be stopped")
}

// Test handling large number of channels
func TestHandleLargeNumberOfChannels(t *testing.T) {
	configPath := "../config.toml"
	node, err := lightning_node.NewNode(configPath)
	assert.NoError(t, err, "Node initialization should not return an error")

	err = node.Start()
	assert.NoError(t, err, "Node should start without error")

	peer := "peer1.synthron.org:9735"
	capacity := int64(100000) // in satoshis

	var channelIDs []string

	for i := 0; i < 100; i++ {
		channelID, err := node.OpenChannel(peer, capacity)
		assert.NoError(t, err, "Opening a payment channel should not return an error")
		assert.NotEmpty(t, channelID, "Channel ID should not be empty")
		channelIDs = append(channelIDs, channelID)
	}

	for _, channelID := range channelIDs {
		err = node.CloseChannel(channelID)
		assert.NoError(t, err, "Closing a payment channel should not return an error")
	}

	err = node.Stop()
	assert.NoError(t, err, "Node should stop without error")
}
