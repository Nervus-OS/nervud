package safety

import "testing"

func BenchmarkTrip(b *testing.B) {
	m := newTestModule()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Trip(ReasonOperatorEStop)
	}
}

func BenchmarkDeliverHalt(b *testing.B) {
	m := newTestModule()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.deliverHalt()
	}
}
