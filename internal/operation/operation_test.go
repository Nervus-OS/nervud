package operation

import "testing"

// TestCanTransition_AllPairs 穷举全部 (from,to) 组合，逐一对照 spec §3 的
// "唯一允许集合"。这是状态机的核心正确性：任何落在集合外的转移都必须被拒。
func TestCanTransition_AllPairs(t *testing.T) {
	all := []State{
		StateUnspecified, StatePending, StateRunning, StateCancelRequested,
		StateSucceeded, StateFailed, StateCancelled,
	}
	allowed := map[[2]State]bool{
		{StatePending, StateRunning}:           true,
		{StatePending, StateCancelRequested}:   true,
		{StatePending, StateFailed}:            true,
		{StateRunning, StateCancelRequested}:   true,
		{StateRunning, StateSucceeded}:         true,
		{StateRunning, StateFailed}:            true,
		{StateCancelRequested, StateSucceeded}: true,
		{StateCancelRequested, StateFailed}:    true,
		{StateCancelRequested, StateCancelled}: true,
	}
	for _, from := range all {
		for _, to := range all {
			want := allowed[[2]State{from, to}]
			if got := canTransition(from, to); got != want {
				t.Errorf("canTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
}

// TestTerminalNoOutgoing 显式钉住：三个终态没有任何合法出边（终态只写一次的
// 结构性保证，铁律 2）。
func TestTerminalNoOutgoing(t *testing.T) {
	all := []State{
		StateUnspecified, StatePending, StateRunning, StateCancelRequested,
		StateSucceeded, StateFailed, StateCancelled,
	}
	for _, from := range []State{StateSucceeded, StateFailed, StateCancelled} {
		for _, to := range all {
			if canTransition(from, to) {
				t.Errorf("terminal %s must have no outgoing edge, but %s→%s allowed", from, from, to)
			}
		}
	}
}

func TestState_Terminal(t *testing.T) {
	term := map[State]bool{StateSucceeded: true, StateFailed: true, StateCancelled: true}
	for _, s := range []State{
		StateUnspecified, StatePending, StateRunning, StateCancelRequested,
		StateSucceeded, StateFailed, StateCancelled,
	} {
		if got := s.Terminal(); got != term[s] {
			t.Errorf("%s.Terminal() = %v, want %v", s, got, term[s])
		}
	}
}

func TestState_String(t *testing.T) {
	if StateUnspecified.String() != "unspecified" {
		t.Errorf("zero State must stringify to unspecified, got %q", StateUnspecified.String())
	}
	if State(200).String() != "unspecified" {
		t.Errorf("unknown State must fail-closed to unspecified")
	}
}
