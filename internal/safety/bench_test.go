package safety

import "testing"

// BenchmarkTrip 测 Safety 触发路径的耗时与分配（-benchmem 应显示 0 allocs/op）。
func BenchmarkTrip(b *testing.B) {
	m := newTestModule()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Trip(ReasonOperatorEStop)
	}
}

// BenchmarkDeliverHalt 测 Stop Lane 投递路径的耗时与分配。
func BenchmarkDeliverHalt(b *testing.B) {
	m := newTestModule()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.deliverHalt()
	}
}
