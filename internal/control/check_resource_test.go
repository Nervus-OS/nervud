package control

import "testing"

func TestCheckResourceRequiresSameConnectionAndResource(t *testing.T) {
	m, _, _ := newTestModule(t)
	lease := mustAcquire(t, m, humanReq(ConnID(11)))

	proof, err := m.CheckResource(ConnID(11), lease.Resource, lease.ResourceGeneration)
	if err != nil {
		t.Fatalf("CheckResource(valid): %v", err)
	}
	if proof.ID != lease.ID || proof.Class != lease.Class || proof.Epoch != lease.Epoch ||
		proof.Resource != lease.Resource || proof.ResourceGeneration != lease.ResourceGeneration ||
		!proof.Deadline.Equal(lease.Deadline) {
		t.Fatalf("proof = %+v, want lease projection of %+v", proof, lease)
	}
	if _, err := m.CheckResource(ConnID(12), lease.Resource, lease.ResourceGeneration); err != ErrControlNotHeld {
		t.Fatalf("wrong connection error=%v, want %v", err, ErrControlNotHeld)
	}
	if _, err := m.CheckResource(ConnID(11), "arm.main", lease.ResourceGeneration); err != ErrControlNotHeld {
		t.Fatalf("wrong resource error=%v, want %v", err, ErrControlNotHeld)
	}
}
