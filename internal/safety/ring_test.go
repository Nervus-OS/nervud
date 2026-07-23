package safety

import (
	"sync"
	"testing"
)

func TestRing_FIFO(t *testing.T) {
	r := newAuditRing(8)
	for i := 1; i <= 5; i++ {
		if !r.push(eventRecord{kind: evTripped, epoch: uint64(i)}) {
			t.Fatalf("push %d should succeed", i)
		}
	}
	for i := 1; i <= 5; i++ {
		rec, ok := r.pop()
		if !ok {
			t.Fatalf("pop %d should succeed", i)
		}
		if rec.epoch != uint64(i) {
			t.Fatalf("pop order: got epoch %d, want %d", rec.epoch, i)
		}
	}
	if _, ok := r.pop(); ok {
		t.Fatal("ring should be empty")
	}
}

func TestRing_DropOnFull(t *testing.T) {
	r := newAuditRing(4)
	for i := 0; i < 4; i++ {
		if !r.push(eventRecord{epoch: uint64(i)}) {
			t.Fatalf("push %d should succeed within capacity", i)
		}
	}
	if r.push(eventRecord{epoch: 99}) {
		t.Fatal("push beyond capacity should be dropped (false)")
	}
	if got := r.droppedCount(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	// 前 4 条仍可完整取回。
	for i := 0; i < 4; i++ {
		rec, ok := r.pop()
		if !ok || rec.epoch != uint64(i) {
			t.Fatalf("pop %d = (%v,%d)", i, ok, rec.epoch)
		}
	}
}

func TestRing_ConcurrentProducers(t *testing.T) {
	// MPSC：多个生产者并发 push，单消费者并发 pop；总取回 + 丢弃 == 总投递，且无撕裂记录。
	// 配合 -race 最有价值。
	const producers = 6
	const each = 5000
	r := newAuditRing(1024)

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// epoch 编码 (生产者 id, 序号)，便于校验无撕裂。
				r.push(eventRecord{kind: evStopProgress, epoch: uint64(id)<<32 | uint64(i)})
			}
		}(p)
	}

	got := 0
	stop := make(chan struct{})
	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		for {
			rec, ok := r.pop()
			if ok {
				if rec.kind != evStopProgress {
					t.Errorf("torn record: kind = %v", rec.kind)
					return
				}
				got++
				continue
			}
			select {
			case <-stop:
				// 生产者已停，再确认排空。
				for {
					if _, ok := r.pop(); !ok {
						return
					}
					got++
				}
			default:
			}
		}
	}()

	wg.Wait()
	close(stop)
	consumerWG.Wait()

	total := producers * each
	if uint64(got)+r.droppedCount() != uint64(total) {
		t.Fatalf("got %d + dropped %d != total %d", got, r.droppedCount(), total)
	}
}

func TestRing_PushAllocFree(t *testing.T) {
	r := newAuditRing(256)
	rec := eventRecord{kind: evHaltDelivered, epoch: 7}
	if n := testing.AllocsPerRun(1000, func() { r.push(rec) }); n != 0 {
		t.Fatalf("push allocs/op = %v, want 0", n)
	}
}
