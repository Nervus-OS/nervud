package control

import "testing"

func TestCheckResourceRequiresSameConnectionAndResource(t *testing.T) {
	m, _, _ := newTestModule(t)
	lease := mustAcquire(t, m, humanReq(ConnID(11)))

	epoch, err := m.CheckResource(ConnID(11), lease.Resource, lease.ResourceGeneration)
	if err != nil {
		t.Fatalf("CheckResource(valid): %v", err)
	}
	if epoch != lease.Epoch {
		t.Fatalf("epoch=%d, want %d", epoch, lease.Epoch)
	}
	if _, err := m.CheckResource(ConnID(12), lease.Resource, lease.ResourceGeneration); err != ErrControlNotHeld {
		t.Fatalf("wrong connection error=%v, want %v", err, ErrControlNotHeld)
	}
	if _, err := m.CheckResource(ConnID(11), "arm.main", lease.ResourceGeneration); err != ErrControlNotHeld {
		t.Fatalf("wrong resource error=%v, want %v", err, ErrControlNotHeld)
	}
}
