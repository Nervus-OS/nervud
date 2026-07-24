package control

import (
	"sync"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func TestConcurrentLifecycle(t *testing.T) {
	m, g, _ := newTestModule(t)

	const rounds = 300
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			l, err := m.Acquire(humanReq(1))
			if err != nil {
				continue
			}
			_, _ = m.Renew(l.ID, l.Conn)
			_, _ = m.Check(l.ID, l.Conn)
			_ = m.Refresh(l.ID, l.Conn)
			_ = m.Release(l.ID, l.Conn)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if l, err := m.Acquire(aiReq(2)); err == nil {
				_ = m.Release(l.ID, l.Conn)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			m.RevokeConn(1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds/10; i++ {
			g.Trip()
			m.RevokeAll(g.Epoch())
			g.RequireRearm()
			g.Rearm()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			m.onTick(time.Now())
		}
	}()

	wg.Wait()

	for i := 0; i < 4 && g.State() != motiongate.StateNormal; i++ {
		g.RequireRearm()
		g.Rearm()
	}
	m.onTick(time.Now())

	if g.State() != motiongate.StateNormal {
		t.Fatalf("gate stuck at %v after rearm attempts", g.State())
	}
	if l := m.cur.Load(); l != nil {
		if _, err := m.Check(l.ID, l.Conn); err != nil {
			t.Fatalf("lease left in the slot is not self-consistent: %v", err)
		}
	}
}
