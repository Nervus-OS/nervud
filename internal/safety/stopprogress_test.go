package safety

import "testing"

func TestStopTracker_MonotonicForward(t *testing.T) {
	var tr stopTracker
	tr.begin(true)

	steps := []StopPhase{PhaseSent, PhaseProviderAccepted, PhaseMCUAcked, PhaseOutputDisabled, PhaseStandstillConfirmed}
	for _, p := range steps {
		if !tr.advance(p) {
			t.Fatalf("advance to %v should succeed", p)
		}
		if tr.phase != p {
			t.Fatalf("phase = %v, want %v", tr.phase, p)
		}
	}
}

func TestStopTracker_RejectsBackward(t *testing.T) {
	var tr stopTracker
	tr.begin(true)
	tr.advance(PhaseOutputDisabled)
	if tr.advance(PhaseSent) {
		t.Fatal("backward advance must be rejected")
	}
	if tr.phase != PhaseOutputDisabled {
		t.Fatalf("phase = %v, want OUTPUT_DISABLED", tr.phase)
	}
}

func TestStopTracker_CapWithoutEvidence(t *testing.T) {
	var tr stopTracker
	tr.begin(false)
	tr.advance(PhaseOutputDisabled)

	if tr.advance(PhaseStandstillConfirmed) {
		t.Fatal("standstill without evidence should not advance past OUTPUT_DISABLED")
	}
	if tr.phase != PhaseOutputDisabled {
		t.Fatalf("phase = %v, want OUTPUT_DISABLED (capped)", tr.phase)
	}
}

func TestStopTracker_CapWithoutEvidence_FromEarlier(t *testing.T) {
	var tr stopTracker
	tr.begin(false)
	tr.advance(PhaseProviderAccepted)
	if !tr.advance(PhaseStandstillConfirmed) {
		t.Fatal("should advance up to the OUTPUT_DISABLED cap")
	}
	if tr.phase != PhaseOutputDisabled {
		t.Fatalf("phase = %v, want OUTPUT_DISABLED", tr.phase)
	}
}

func TestStopTracker_TerminalFaultIsSticky(t *testing.T) {
	var tr stopTracker
	tr.begin(true)
	tr.advance(PhaseSent)
	if !tr.advance(PhaseDeliveryFault) {
		t.Fatal("fault should be reachable")
	}
	if tr.advance(PhaseOutputDisabled) || tr.advance(PhaseStandstillConfirmed) {
		t.Fatal("no advance out of a terminal fault")
	}
	if tr.phase != PhaseDeliveryFault {
		t.Fatalf("phase = %v, want DELIVERY_FAULT", tr.phase)
	}
}
