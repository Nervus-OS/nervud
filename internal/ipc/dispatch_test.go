package ipc

import (
	"sync"
	"testing"
	"time"
)

// fakeConn 只是给 dispatchTable 的单测提供可比较的连接身份用——本文件测试的
// 是表本身的语义,不涉及真实 socket,所以不需要一个功能完整的 *conn
func fakeConn() *conn { return &conn{} }

func TestDispatchTable_CreateAssignsMonotonicNonZeroIDs(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()

	id1 := tbl.create(src, 1, tgt, time.Now().Add(time.Second))
	id2 := tbl.create(src, 2, tgt, time.Now().Add(time.Second))

	if id1 == 0 || id2 == 0 {
		t.Fatalf("route_id 不该是 0: id1=%d id2=%d", id1, id2)
	}
	if id2 <= id1 {
		t.Fatalf("route_id 应当严格递增: id1=%d id2=%d", id1, id2)
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
		t.Fatalf("entry 内容不符: %+v", e)
	}

	// 完成之后表项必须被删除:第二次 complete 应当是 completeNotFound
	if _, status := tbl.complete(id, tgt); status != completeNotFound {
		t.Fatalf("重复 complete 的 status = %v, want completeNotFound", status)
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
	// 错位不会误删表项:真正的目标随后仍能正常完成
	if _, status := tbl.complete(id, tgt); status != completeOK {
		t.Fatalf("错位之后,真正的目标 complete 的 status = %v, want completeOK", status)
	}
}

func TestDispatchTable_CompleteAny(t *testing.T) {
	tbl := newDispatchTable()
	src, tgt := fakeConn(), fakeConn()
	id := tbl.create(src, 1, tgt, time.Now().Add(time.Second))

	e, ok := tbl.completeAny(id)
	if !ok || e.routeID != id {
		t.Fatalf("completeAny 失败: ok=%v e=%+v", ok, e)
	}
	if _, ok := tbl.completeAny(id); ok {
		t.Fatal("重复 completeAny 应当返回 ok=false")
	}
}

func TestDispatchTable_ConnClosedPartitionsByRole(t *testing.T) {
	tbl := newDispatchTable()
	a, b, c := fakeConn(), fakeConn(), fakeConn()

	// a 是 route1 的 source、route2 的 target;b 与 c 是无关连接,不该被影响
	id1 := tbl.create(a, 1, b, time.Now().Add(time.Second))
	id2 := tbl.create(c, 2, a, time.Now().Add(time.Second))
	idUnrelated := tbl.create(b, 3, c, time.Now().Add(time.Second))

	asTarget, asSource := tbl.connClosed(a)
	if len(asTarget) != 1 || asTarget[0].routeID != id2 {
		t.Fatalf("asTarget 应当只含 route2: %+v", asTarget)
	}
	if len(asSource) != 1 || asSource[0].routeID != id1 {
		t.Fatalf("asSource 应当只含 route1: %+v", asSource)
	}

	// 两条都应该已从表中删除
	if _, ok := tbl.completeAny(id1); ok {
		t.Fatal("route1 应当已被 connClosed 删除")
	}
	if _, ok := tbl.completeAny(id2); ok {
		t.Fatal("route2 应当已被 connClosed 删除")
	}
	// 无关的 route 不受影响
	if _, ok := tbl.completeAny(idUnrelated); !ok {
		t.Fatal("无关的 route 不该被 connClosed 影响")
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
		t.Fatalf("reap 结果不符: %+v", expired)
	}
	// 未过期的表项必须原封不动
	if _, ok := tbl.completeAny(liveID); !ok {
		t.Fatal("未过期的表项不该被 reap 摘掉")
	}
	// 已过期的表项已经被删除
	if _, ok := tbl.completeAny(expiredID); ok {
		t.Fatal("已过期的表项应当已被 reap 删除")
	}
}

// TestDispatchTable_ConcurrentCompleteIsExactlyOnce 在 -race 下验证同一个
// route_id 被 complete/completeAny 并发竞争时,不会被完成两次——这是“表锁下
// 删除即唯一完成者”这条设计不变量的直接压力测试
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
	completedBy := make(map[uint64]int) // routeID -> 完成次数,必须恰好为 1

	record := func(id uint64) {
		mu.Lock()
		completedBy[id]++
		mu.Unlock()
	}

	for _, id := range ids {
		wg.Add(2)
		id := id
		// 两条路径互相竞争完成同一个 route:complete(正确 target)、completeAny
		// (模拟清道夫/立即失败路径)。哪一个先拿到表锁并删除表项,谁就该赢
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
			t.Fatalf("route %d 被完成 %d 次, want 恰好 1 次", id, completedBy[id])
		}
	}
}

// TestDispatchTable_ConnClosedConcurrentWithCreate 在 -race 下验证 connClosed
// 与 create 并发发生时不产生数据竞争(表锁保护读写),且不会遗漏或重复摘除
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
			t.Fatalf("route %d 在 connClosed 时被遗漏", id)
		}
	}
	if len(asTarget) != n {
		t.Fatalf("asTarget 数量 = %d, want %d", len(asTarget), n)
	}
}
