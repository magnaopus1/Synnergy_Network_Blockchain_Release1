package flowcontrol

import (
	"sync"
	"time"
)

// Throttler controls the rate of data transmission.
type Throttler struct {
	rate     int
	interval time.Duration
	ticker   *time.Ticker
	lock     sync.Mutex
}

// NewThrottler initializes a new Throttler with a specific rate.
func NewThrottler(rate int) *Throttler {
	interval := time.Second / time.Duration(rate)
	return &Throttler{
		rate:     rate,
		interval: interval,
		ticker:   time.NewTicker(interval),
	}
}

// SetRate adjusts the rate of data transmission.
func (t *Throttler) SetRate(newRate int) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.rate = newRate
	t.interval = time.Second / time.Duration(newRate)
	t.ticker.Reset(t.interval)
}

// Transmit simulates the transmission of data, controlled by the throttle.
func (t *Throttler) Transmit(data []byte, done chan<- bool) {
	go func() {
		for _, b := range data {
			<-t.ticker.C
			t.send(b)
		}
		done <- true
	}()
}

// send represents the lower-level operation of sending a data byte.
func (t *Throttler) send(b byte) {
	// Simulate sending a byte over the network.
}

// Stop ceases the throttling operation.
func (t *Throttler) Stop() {
	t.ticker.Stop()
}

func main() {
	throttler := NewThrottler(10) // Set initial transmission rate to 10 bytes per second.
	done := make(chan bool)
	data := []byte("Data to transmit over Synnergy Network")

	throttler.Transmit(data, done)
	<-done // Wait for transmission to complete.

	throttler.SetRate(20) // Adjust the rate dynamically if needed.
	throttler.Stop()      // Stop the throttler when finished.
}
