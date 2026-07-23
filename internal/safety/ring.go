package safety

import "sync/atomic"

// eventKind 是审计事件的固定分类，供零堆分配的审计 ring 使用。
type eventKind uint8

const (
	evTripped               eventKind = iota + 1 // Trip 导致锁存（Supervisor 观察到）
	evHaltDelivered                              // Stop Lane 已投递固定停机信号
	evDeliveryFault                              // Stop Lane 投递失败
	evStopProgress                               // StopProgress 相位推进
	evProviderAcceptTimeout                      // provider_accept_timeout 触发升级
	evDeviceAckTimeout                           // device_stop_ack_timeout 触发升级
	evStandstillTimeout                          // standstill_timeout 触发升级
	evStandstillConfirmed                        // 取得可信停稳证据
	evRearm                                      // 经明确 re-arm 回到 NORMAL
)

func (k eventKind) String() string {
	switch k {
	case evTripped:
		return "tripped"
	case evHaltDelivered:
		return "halt_delivered"
	case evDeliveryFault:
		return "delivery_fault"
	case evStopProgress:
		return "stop_progress"
	case evProviderAcceptTimeout:
		return "provider_accept_timeout"
	case evDeviceAckTimeout:
		return "device_ack_timeout"
	case evStandstillTimeout:
		return "standstill_timeout"
	case evStandstillConfirmed:
		return "standstill_confirmed"
	case evRearm:
		return "rearm"
	default:
		return "unknown"
	}
}

// eventRecord 是一条固定大小、无指针的审计记录：可整块预分配、按值拷贝入 ring，
// 写入零堆分配。语义细节（字符串化）留到普通优先级的 auditDrain（架构 §6 item4）。
type eventRecord struct {
	kind   eventKind
	reason ReasonCode
	phase  StopPhase
	epoch  uint64
}

// auditRing 是有界、lock-free 的多生产者单消费者队列（Vyukov bounded MPMC 队列的
// MPSC 用法）：
//
//   - 生产者 = Stop Lane(FIFO 95) + Supervisor(FIFO 90)，都在 RT 线程的热路径上；
//     push 不加锁、不分配、绝不阻塞。ring 满则丢弃并计数（dropped）——审计延迟/丢失
//     远优于拖住 RT 停机路径（架构 §6 item4；§10.11：审计可限速）。
//   - 消费者 = auditDrain（普通优先级 SCHED_OTHER），pop 后再做字符串化与落库。
//
// 每个 cell 带一个 seq 序号，充当「该格当前属于哪一轮、可写还是可读」的门闩，
// 从而无需互斥锁即可安全交接。size 必须是 2 的幂。
type auditRing struct {
	buf     []ringCell
	mask    uint64
	enqPos  atomic.Uint64 // 生产者的写游标（单调递增）
	deqPos  atomic.Uint64 // 消费者的读游标（单调递增）
	dropped atomic.Uint64
}

type ringCell struct {
	seq atomic.Uint64
	rec eventRecord
}

// newAuditRing 构造容量为 size（须为 2 的幂）的 ring，并把每个 cell 的 seq 初始化为
// 其下标——这是 Vyukov 队列「空队列」的起始条件。
func newAuditRing(size int) *auditRing {
	r := &auditRing{buf: make([]ringCell, size), mask: uint64(size - 1)}
	for i := range r.buf {
		r.buf[i].seq.Store(uint64(i))
	}
	return r
}

// push 入队一条记录。成功返回 true；ring 满返回 false 并递增 dropped。
// lock-free、零堆分配，可在 RT 热路径调用。
func (r *auditRing) push(rec eventRecord) bool {
	for {
		pos := r.enqPos.Load()
		cell := &r.buf[pos&r.mask]
		seq := cell.seq.Load()
		dif := int64(seq) - int64(pos)
		switch {
		case dif == 0:
			// 该格空闲且轮到本轮写：抢占写游标。
			if r.enqPos.CompareAndSwap(pos, pos+1) {
				cell.rec = rec
				cell.seq.Store(pos + 1) // 发布：seq=pos+1 表示「可读」
				return true
			}
		case dif < 0:
			// 该格还没被消费者读走（seq 落后）：队列满。
			r.dropped.Add(1)
			return false
		default:
			// 另一个生产者已经推进了 enqPos，重读重试。
		}
	}
}

// pop 出队一条记录（仅单一消费者调用）。空则返回 (零值, false)。
func (r *auditRing) pop() (eventRecord, bool) {
	for {
		pos := r.deqPos.Load()
		cell := &r.buf[pos&r.mask]
		seq := cell.seq.Load()
		dif := int64(seq) - int64(pos+1)
		switch {
		case dif == 0:
			// 该格已被生产者发布且轮到本轮读：抢占读游标。
			if r.deqPos.CompareAndSwap(pos, pos+1) {
				rec := cell.rec
				cell.seq.Store(pos + r.mask + 1) // 归还：标记为下一轮可写
				return rec, true
			}
		case dif < 0:
			// 该格尚未发布：队列空。
			return eventRecord{}, false
		default:
		}
	}
}

func (r *auditRing) droppedCount() uint64 { return r.dropped.Load() }
