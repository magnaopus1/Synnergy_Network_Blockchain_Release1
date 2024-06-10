package mesh_networking

import (
	"log"
	"math"
	"net"
	"sync"
	"time"
)

type LinkQuality struct {
	Latency    time.Duration
	PacketLoss float64
	SignalStrength float64
}

// LinkQualityMetrics manages adaptive link quality metrics
type LinkQualityMetrics struct {
	mu         sync.RWMutex
	metrics    map[string]LinkQuality
	updateChan chan struct{}
}

// NewLinkQualityMetrics initializes a new LinkQualityMetrics
func NewLinkQualityMetrics() *LinkQualityMetrics {
	lqm := &LinkQualityMetrics{
		metrics:    make(map[string]LinkQuality),
		updateChan: make(chan struct{}),
	}
	go lqm.updateMetrics()
	return lqm
}

// updateMetrics periodically updates link quality metrics
func (lqm *LinkQualityMetrics) updateMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ticker.C:
			lqm.mu.Lock()
			for peer := range lqm.metrics {
				// Simulate updating metrics (this should be replaced with real measurements)
				lqm.metrics[peer] = LinkQuality{
					Latency:        time.Duration(math.Floor(10 + 10*rand.Float64())) * time.Millisecond,
					PacketLoss:     math.Floor(5*rand.Float64()) / 100,
					SignalStrength: math.Floor(50 + 50*rand.Float64()),
				}
			}
			lqm.mu.Unlock()
		case <-lqm.updateChan:
			return
		}
	}
}

// AddPeer adds a new peer with initial link quality metrics
func (lqm *LinkQualityMetrics) AddPeer(peerID string, quality LinkQuality) {
	lqm.mu.Lock()
	defer lqm.mu.Unlock()
	lqm.metrics[peerID] = quality
}

// RemovePeer removes a peer from the metrics tracking
func (lqm *LinkQualityMetrics) RemovePeer(peerID string) {
	lqm.mu.Lock()
	defer lqm.mu.Unlock()
	delete(lqm.metrics, peerID)
}

// GetPeerQuality retrieves the link quality metrics for a peer
func (lqm *LinkQualityMetrics) GetPeerQuality(peerID string) (LinkQuality, bool) {
	lqm.mu.RLock()
	defer lqm.mu.RUnlock()
	quality, exists := lqm.metrics[peerID]
	return quality, exists
}

// AdjustRouting adjusts routing decisions based on link quality metrics
func (lqm *LinkQualityMetrics) AdjustRouting() {
	lqm.mu.RLock()
	defer lqm.mu.RUnlock()
	for peer, quality := range lqm.metrics {
		log.Printf("Adjusting routing for peer %s: Latency=%v, PacketLoss=%.2f, SignalStrength=%.2f", peer, quality.Latency, quality.PacketLoss, quality.SignalStrength)
		// Add routing logic here based on the quality metrics
	}
}

// Stop stops the metric update routine
func (lqm *LinkQualityMetrics) Stop() {
	close(lqm.updateChan)
}

func main() {
	lqm := NewLinkQualityMetrics()
	defer lqm.Stop()

	peer1 := "peer1"
	peer2 := "peer2"
	peer3 := "peer3"

	lqm.AddPeer(peer1, LinkQuality{Latency: 20 * time.Millisecond, PacketLoss: 0.01, SignalStrength: 80})
	lqm.AddPeer(peer2, LinkQuality{Latency: 30 * time.Millisecond, PacketLoss: 0.05, SignalStrength: 75})
	lqm.AddPeer(peer3, LinkQuality{Latency: 25 * time.Millisecond, PacketLoss: 0.02, SignalStrength: 90})

	// Simulate periodic adjustments
	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-ticker.C:
			lqm.AdjustRouting()
		}
	}
}

// Utility Functions

// MeasureLatency measures the latency to a given peer
func MeasureLatency(addr string) time.Duration {
	start := time.Now()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return time.Duration(math.MaxInt64)
	}
	conn.Close()
	return time.Since(start)
}

// MeasurePacketLoss measures the packet loss to a given peer
func MeasurePacketLoss(addr string, numPackets int) float64 {
	lostPackets := 0
	for i := 0; i < numPackets; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			lostPackets++
			continue
		}
		conn.Close()
	}
	return float64(lostPackets) / float64(numPackets)
}

// MeasureSignalStrength measures the signal strength to a given peer
func MeasureSignalStrength(addr string) float64 {
	// Placeholder for actual signal strength measurement
	return 100.0
}
