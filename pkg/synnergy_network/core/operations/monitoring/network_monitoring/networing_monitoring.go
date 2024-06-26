package network_monitoring

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/node_connectivity"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/performance_metrics"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/data_propagation"
	"github.com/synthron_blockchain_final/pkg/layer0/monitoring/network_monitoring/geographical_visualization"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type NetworkMonitor struct {
	nodeManager           *node_connectivity.NodeConnectivityManager
	metricsManager        *performance_metrics.PerformanceMetricsManager
	dataPropagation       *data_propagation.DataPropagationAnalyzer
	geoVisualization      *geographical_visualization.GeoVisualization
	alertManager          *AlertManager
	peerCommunicator      *PeerCommunicator
}

type AlertManager struct {
	alertThreshold int
	alertChan      chan string
}

func NewAlertManager(threshold int) *AlertManager {
	return &AlertManager{
		alertThreshold: threshold,
		alertChan:      make(chan string),
	}
}

func (am *AlertManager) StartMonitoring(ncm *node_connectivity.NodeConnectivityManager) {
	go func() {
		for {
			time.Sleep(1 * time.Minute) // Check every minute
			am.checkForAlerts(ncm)
		}
	}()
}

func (am *AlertManager) checkForAlerts(ncm *node_connectivity.NodeConnectivityManager) {
	nodes := ncm.GetAllNodesStatus()
	disconnectedNodes := 0
	for _, node := range nodes {
		if !node.Connected {
			disconnectedNodes++
		}
	}
	if disconnectedNodes >= am.alertThreshold {
		alert := am.createAlert(disconnectedNodes)
		log.Println(alert)
		am.alertChan <- alert
	}
}

func (am *AlertManager) createAlert(disconnectedNodes int) string {
	return log.Sprintf("Alert: %d nodes are disconnected", disconnectedNodes)
}

func (am *AlertManager) GetAlertChannel() <-chan string {
	return am.alertChan
}

type SecureCommunicator struct {
	key []byte
}

func NewSecureCommunicator(passphrase string) (*SecureCommunicator, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return &SecureCommunicator{key: key}, nil
}

func (sc *SecureCommunicator) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (sc *SecureCommunicator) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

type PeerCommunicator struct {
	ncm             *node_connectivity.NodeConnectivityManager
	secureComm      *SecureCommunicator
	communicationCh chan *PeerMessage
}

type PeerMessage struct {
	FromNodeID string `json:"from_node_id"`
	ToNodeID   string `json:"to_node_id"`
	Data       []byte `json:"data"`
	Timestamp  int64  `json:"timestamp"`
}

func NewPeerCommunicator(ncm *node_connectivity.NodeConnectivityManager, secureComm *SecureCommunicator) *PeerCommunicator {
	return &PeerCommunicator{
		ncm:             ncm,
		secureComm:      secureComm,
		communicationCh: make(chan *PeerMessage),
	}
}

func (pc *PeerCommunicator) SendMessage(fromNodeID, toNodeID string, data []byte) error {
	encryptedData, err := pc.secureComm.Encrypt(data)
	if err != nil {
		return err
	}
	message := &PeerMessage{
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
		Data:       encryptedData,
		Timestamp:  time.Now().Unix(),
	}
	pc.communicationCh <- message
	return nil
}

func (pc *PeerCommunicator) ReceiveMessage() (*PeerMessage, error) {
	message := <-pc.communicationCh
	decryptedData, err := pc.secureComm.Decrypt(message.Data)
	if err != nil {
		return nil, err
	}
	message.Data = decryptedData
	return message, nil
}

func (pc *PeerCommunicator) BroadcastMessage(fromNodeID string, data []byte) {
	encryptedData, err := pc.secureComm.Encrypt(data)
	if err != nil {
		log.Println("Failed to encrypt data for broadcast:", err)
		return
	}
	pc.ncm.mutex.Lock()
	for nodeID, status := range pc.ncm.nodes {
		if status.Connected && nodeID != fromNodeID {
			message := &PeerMessage{
				FromNodeID: fromNodeID,
				ToNodeID:   nodeID,
				Data:       encryptedData,
				Timestamp:  time.Now().Unix(),
			}
			pc.communicationCh <- message
		}
	}
	pc.ncm.mutex.Unlock()
}

func (pc *PeerCommunicator) HandlePeerCommunication() {
	go func() {
		for {
			message := <-pc.communicationCh
			log.Printf("Received message from %s to %s at %d\n", message.FromNodeID, message.ToNodeID, message.Timestamp)
			// Process the message as needed
		}
	}()
}

func NewNetworkMonitor() *NetworkMonitor {
	ncm := node_connectivity.NewNodeConnectivityManager()
	metricsManager := performance_metrics.NewPerformanceMetricsManager()
	dataPropagation := data_propagation.NewDataPropagationAnalyzer()
	geoVisualization := geographical_visualization.NewGeoVisualization()
	alertManager := NewAlertManager(5)
	secureComm, err := NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}
	peerCommunicator := NewPeerCommunicator(ncm, secureComm)

	return &NetworkMonitor{
		nodeManager:           ncm,
		metricsManager:        metricsManager,
		dataPropagation:       dataPropagation,
		geoVisualization:      geoVisualization,
		alertManager:          alertManager,
		peerCommunicator:      peerCommunicator,
	}
}

func (nm *NetworkMonitor) StartMonitoring() {
	go nm.nodeManager.CheckAllNodesConnectivity()
	go nm.metricsManager.StartCollectingMetrics()
	go nm.dataPropagation.AnalyzeDataPropagation()
	go nm.geoVisualization.VisualizeGeographicalData()
	nm.alertManager.StartMonitoring(nm.nodeManager)
	nm.peerCommunicator.HandlePeerCommunication()
}

func (nm *NetworkMonitor) ServeHTTP(port string) {
	http.HandleFunc("/nodes", nm.handleNodesRequest)
	http.HandleFunc("/metrics", nm.handleMetricsRequest)
	http.HandleFunc("/alerts", nm.handleAlertsRequest)
	log.Printf("Serving network monitoring status on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (nm *NetworkMonitor) handleNodesRequest(w http.ResponseWriter, r *http.Request) {
	nodes := nm.nodeManager.GetAllNodesStatus()
	data, err := json.Marshal(nodes)
	if err != nil {
		http.Error(w, "Failed to marshal nodes status", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (nm *NetworkMonitor) handleMetricsRequest(w http.ResponseWriter, r *http.Request) {
	metrics := nm.metricsManager.GetMetrics()
	data, err := json.Marshal(metrics)
	if err != nil {
		http.Error(w, "Failed to marshal metrics", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (nm *NetworkMonitor) handleAlertsRequest(w http.ResponseWriter, r *http.Request) {
	alerts := make([]string, 0)
	alertChan := nm.alertManager.GetAlertChannel()
	for {
		select {
		case alert := <-alertChan:
			alerts = append(alerts, alert)
		default:
			data, err := json.Marshal(alerts)
			if err != nil {
				http.Error(w, "Failed to marshal alerts", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}
	}
}

func main() {
	nm := NewNetworkMonitor()
	nm.StartMonitoring()
	nm.ServeHTTP("8080")
}
