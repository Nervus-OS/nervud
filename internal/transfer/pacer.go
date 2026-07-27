package transfer

import (
	"errors"
	"sync"
	"time"
)

// pacer is shared by both directions of a bidirectional Transfer, so
// max_bytes_per_second is conservatively an aggregate cap.
type pacer struct {
	mu       sync.Mutex
	bytesPS  uint64
	framesPS uint32
	next     time.Time
}

func newPacer(bytesPS uint64, framesPS uint32) *pacer {
	return &pacer{bytesPS: bytesPS, framesPS: framesPS}
}

func (p *pacer) reserve(now time.Time, bytes uint64, maxDelay time.Duration) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bytesPS == 0 || p.framesPS == 0 {
		return 0, errors.New("transfer: zero relay rate")
	}
	if p.next.Before(now) {
		p.next = now
	}
	delay := p.next.Sub(now)
	if delay > maxDelay {
		return 0, errors.New("transfer: relay rate backlog exceeded")
	}
	byteInterval := durationForRate(bytes, p.bytesPS)
	frameInterval := time.Second / time.Duration(p.framesPS)
	if byteInterval < frameInterval {
		byteInterval = frameInterval
	}
	p.next = p.next.Add(byteInterval)
	return delay, nil
}

func durationForRate(n, perSecond uint64) time.Duration {
	if n == 0 || perSecond == 0 {
		return 0
	}
	seconds := float64(n) / float64(perSecond)
	d := time.Duration(seconds * float64(time.Second))
	if d <= 0 {
		return time.Nanosecond
	}
	return d
}
