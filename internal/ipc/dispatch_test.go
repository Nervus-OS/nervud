package ipc

import (
	"sync"
	"testing"
	"time"
)

func fakeConn() *conn { return &conn{} }

func TestDispatchTable_CreateAssignsMonotonicNonZeroIDs(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()

	id1 := tbl.create(src, 1, tgt, time.Now().Add(time.Second))
	id2 := tbl.create(src, 2, tgt, time.Now().Add(time.Second))

	if id1 == 0 || id2 == 0 {
		t.Fatalf("route_id must not be 0: id1=%d id2=%d", id1, id2)
	}
	if id2 <= id1 {
		t.Fatalf("route_id should increase strictly: id1=%d id2=%d", id1, id2)
	}
}

func TestDispatchTable_CompleteSuccess(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()
	id := tbl.create(src, 42, tgt, time.Now().Add(time.Second))

	e, status := tbl.complete(id, tgt)
	if status != completeOK {
		t.Fatalf("status = %v, want completeOK", status)
	}
	if e.sourceRequestID != 42 || e.source != src || e.target != tgt {
		t.Fatalf("entry content mismatch: %+v", e)
	}

	if _, status := tbl.complete(id, tgt); status != completeNotFound {
		t.Fatalf("duplicate complete status = %v, want completeNotFound", status)
	}
}

func TestDispatchTable_CompleteUnknownRouteID(t *testing.T) {
	tbl := newDispatchTable()
	if _, status := tbl.complete(999, fakeConn()); status != completeNotFound {
		t.Fatalf("status = %v, want completeNotFound", status)
	}
}

func TestDispatchTable_CompleteTargetMismatch(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt, other := fakeConn(), fakeConn(), fakeConn()
	id := tbl.create(src, 1, tgt, time.Now().Add(time.Second))

	if _, status := tbl.complete(id, other); status != completeMismatch {
		t.Fatalf("status = %v, want completeMismatch", status)
	}
	if _, status := tbl.complete(id, tgt); status != completeOK {
		t.Fatalf("target complete status after mismatch = %v, want completeOK", status)
	}
}

func TestDispatchTable_CompleteAny(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()
	id := tbl.create(src, 1, tgt, time.Now().Add(time.Second))

	e, ok := tbl.completeAny(id)
	if !ok || e.routeID != id {
		t.Fatalf("completeAny failed: ok=%v e=%+v", ok, e)
	}
	if _, ok := tbl.completeAny(id); ok {
		t.Fatal("duplicate completeAny should return ok=false")
	}
}

func TestDispatchTable_ConnClosedPartitionsByRole(t *testing.T) {
	tbl := newDispatchTable()
	a, b, c := fakeConn(), fakeConn(), fakeConn()

	id1 := tbl.create(a, 1, b, time.Now().Add(time.Second))
	id2 := tbl.create(c, 2, a, time.Now().Add(time.Second))
	idUnrelated := tbl.create(b, 3, c, time.Now().Add(time.Second))

	asTarget, asSource := tbl.connClosed(a)
	if len(asTarget) != 1 || asTarget[0].routeID != id2 {
		t.Fatalf("asTarget should contain only route2: %+v", asTarget)
	}
	if len(asSource) != 1 || asSource[0].routeID != id1 {
		t.Fatalf("asSource should contain only route1: %+v", asSource)
	}

	if _, ok := tbl.completeAny(id1); ok {
		t.Fatal("route1 should have been removed by connClosed")
	}
	if _, ok := tbl.completeAny(id2); ok {
		t.Fatal("route2 should have been removed by connClosed")
	}
	if _, ok := tbl.completeAny(idUnrelated); !ok {
		t.Fatal("connClosed should not affect an unrelated route")
	}
}

func TestDispatchTable_Reap(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()

	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)
	expiredID := tbl.create(src, 1, tgt, past)
	liveID := tbl.create(src, 2, tgt, future)

	expired := tbl.reap(time.Now())
	if len(expired) != 1 || expired[0].routeID != expiredID {
		t.Fatalf("reap result mismatch: %+v", expired)
	}
	if _, ok := tbl.completeAny(liveID); !ok {
		t.Fatal("reap should not remove an unexpired entry")
	}
	if _, ok := tbl.completeAny(expiredID); ok {
		t.Fatal("reap should remove an expired entry")
	}
}

func TestDispatchTable_ConcurrentCompleteIsExactlyOnce(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()

	const n = 200
	ids := make([]uint64, n)
	for i := range ids {
		ids[i] = tbl.create(src, uint64(i), tgt, time.Now().Add(time.Minute))
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	completedBy := make(map[uint64]int)

	record := func(id uint64) {
		mu.Lock()
		completedBy[id]++
		mu.Unlock()
	}

	for _, id := range ids {
		wg.Add(2)
		id := id
		go func() {
			defer wg.Done()
			if _, status := tbl.complete(id, tgt); status == completeOK {
				record(id)
			}
		}()
		go func() {
			defer wg.Done()
			if _, ok := tbl.completeAny(id); ok {
				record(id)
			}
		}()
	}
	wg.Wait()

	for _, id := range ids {
		if completedBy[id] != 1 {
			t.Fatalf("route %d completed %d times, want exactly once", id, completedBy[id])
		}
	}
}

func TestDispatchTable_ConnClosedConcurrentWithCreate(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()

	const n = 200
	var wg sync.WaitGroup
	ids := make(chan uint64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids <- tbl.create(src, uint64(i), tgt, time.Now().Add(time.Minute))
		}(i)
	}
	wg.Wait()
	close(ids)

	asTarget, _ := tbl.connClosed(tgt)

	seen := make(map[uint64]bool, len(asTarget))
	for _, e := range asTarget {
		seen[e.routeID] = true
	}
	for id := range ids {
		if !seen[id] {
			t.Fatalf("route %d was missed by connClosed", id)
		}
	}
	if len(asTarget) != n {
		t.Fatalf("asTarget count = %d, want %d", len(asTarget), n)
	}
}
