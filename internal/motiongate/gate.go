package motiongate

import "sync/atomic"

const (
	epochBits  = 56
	epochMask  = (uint64(1) << epochBits) - 1 // 低 56 位
	stateShift = epochBits                    // State 位于高 8 位
)

// Gate 是打包 [高8位 State | 低56位 epoch] 的原子核心。见包文档的布局与不变量。
//
// 零值 Gate 不可用（解出 StateInvalid/epoch 0）；必须经 New() 构造。字段私有，
// 只经方法原子读写，禁止直接触碰 word。
type Gate struct {
	word atomic.Uint64
}

// New 构造一个处于 Normal、epoch=1 的 Gate。epoch 恒非零（NRCP §10.5）。
func New() *Gate {
	g := &Gate{}
	g.word.Store(pack(StateNormal, 1))
	return g
}

func pack(s State, epoch uint64) uint64 {
	return uint64(s)<<stateShift | epoch&epochMask
}

func unpack(word uint64) (State, uint64) {
	return State(word >> stateShift), word & epochMask
}

// incEpoch 递增 epoch，保持在 56 位内，且永不落到 0（0 是无效世代）。
//
// 56 位世代号在现实中不可能耗尽（即便每微秒递增一次也要两千年以上）；万一回绕，
// 也显式跳过 0，维持「epoch 恒非零」这一 fail-closed 不变量。
func incEpoch(e uint64) uint64 {
	ne := (e + 1) & epochMask
	if ne == 0 {
		ne = 1
	}
	return ne
}

// Snapshot 一次原子 Load 返回一致的 (state, epoch)。adapter/dispatch 复核运动
// 前置条件时用它，避免分别读两个字段读到撕裂状态。零堆分配。
func (g *Gate) Snapshot() (State, uint64) { return unpack(g.word.Load()) }

// State 原子读当前状态。
func (g *Gate) State() State { s, _ := unpack(g.word.Load()); return s }

// Epoch 原子读当前 motion epoch。
func (g *Gate) Epoch() uint64 { _, e := unpack(g.word.Load()); return e }

// Trip 触发 Safety：
//
//   - 当前非 SafetyLatched → 置 SafetyLatched 并递增 epoch，返回 true；
//   - 当前已 SafetyLatched → 不做任何改动，返回 false（幂等，不 churn epoch）。
//
// 从 OEMRecovery / RearmRequired 触发同样会重新 latch 并递增 epoch，废止恢复阶段
// 的残留命令（NRCP §10.5 表：Safety 触发立即递增）。锁存在本调用返回时即刻生效，
// 不依赖任何 Lane 调度（架构 §14.1）。lock-free、零堆分配——可直接在 Safety 触发
// 热路径调用。
func (g *Gate) Trip() bool {
	for {
		old := g.word.Load()
		s, e := unpack(old)
		if s == StateSafetyLatched {
			return false
		}
		if g.word.CompareAndSwap(old, pack(StateSafetyLatched, incEpoch(e))) {
			return true
		}
	}
}

// BumpEpoch 只递增 epoch、保留当前 State：供 control 的 lease 生命周期事件
// （从 NONE 签发、HUMAN 抢占 AI、释放/超时/连接断开/deadman 失效等，NRCP §10.5）
// 使用，让已进入 Provider 队列的旧命令整体作废。lock-free、零堆分配。
func (g *Gate) BumpEpoch() {
	for {
		old := g.word.Load()
		s, e := unpack(old)
		if g.word.CompareAndSwap(old, pack(s, incEpoch(e))) {
			return
		}
	}
}

// BeginRecovery：SafetyLatched → OEMRecovery（epoch 不变）。非该源态返回 false。
// 进入 OEM 恢复阶段仍在安全语义下，不解除 latch。
func (g *Gate) BeginRecovery() bool { return g.cas1(StateSafetyLatched, StateOEMRecovery, false) }

// RequireRearm：SafetyLatched 或 OEMRecovery → RearmRequired（epoch 不变）。
// 表示「必须经明确 re-arm 才能回 Normal」。非该两源态返回 false。
func (g *Gate) RequireRearm() bool {
	for {
		old := g.word.Load()
		s, e := unpack(old)
		if s != StateSafetyLatched && s != StateOEMRecovery {
			return false
		}
		if g.word.CompareAndSwap(old, pack(StateRearmRequired, e)) {
			return true
		}
	}
}

// Rearm：RearmRequired → Normal 并递增 epoch（NRCP §14.4 item4 / §10.5：re-arm 后
// 再递增一次、从 NONE 开始，废止恢复阶段残留命令）。非该源态返回 false。
func (g *Gate) Rearm() bool { return g.cas1(StateRearmRequired, StateNormal, true) }

// cas1 是单一源态的 CAS 迁移：仅当前态 == from 才迁到 to（bump 时同时递增 epoch），
// 成功返回 true；期间若被并发 Trip 改写导致源态不符，返回 false 让调用方按当前
// 真实状态重新决策。
func (g *Gate) cas1(from, to State, bump bool) bool {
	for {
		old := g.word.Load()
		s, e := unpack(old)
		if s != from {
			return false
		}
		ne := e
		if bump {
			ne = incEpoch(e)
		}
		if g.word.CompareAndSwap(old, pack(to, ne)) {
			return true
		}
	}
}
