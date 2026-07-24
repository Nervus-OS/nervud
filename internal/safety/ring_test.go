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
	for i := 0; i < 4; i++ {
		rec, ok := r.pop()
		if !ok || rec.epoch != uint64(i) {
			t.Fatalf("pop %d = (%v,%d)", i, ok, rec.epoch)
		}
	}
}

func TestRing_ConcurrentProducers(t *testing.T) {
	const producers = 6
	const each = 5000
	r := newAuditRing(1024)

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
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
