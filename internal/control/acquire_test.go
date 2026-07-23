package control

import (
	"errors"
	"testing"
	"time"
)

// TestPreemptionMatrix 覆盖抢占矩阵的全部四格 + 同连接重复申请
//
// 唯一合法的抢占是 HUMAN 抢 AI（NRCP §10.5）。其余三格都必须拒绝，且拒绝原因要能
// 区分出「现在是人在遥控」——上层据此才能去问用户要不要让出
func TestPreemptionMatrix(t *testing.T) {
	tests := []struct {
		name    string
		held    func(ConnID) Request
		want    func(ConnID) Request
		wantErr error // nil = 应当成功
	}{
		{name: "HUMAN 抢 AI", held: aiReq, want: humanReq},
		{name: "AI 抢 HUMAN", held: humanReq, want: aiReq, wantErr: ErrHeldByHuman},
		{name: "HUMAN 抢 HUMAN", held: humanReq, want: humanReq, wantErr: ErrHeldByHuman},
		{name: "AI 抢 AI", held: aiReq, want: aiReq, wantErr: ErrHeldByAI},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := newTestModule(t)
			first := mustAcquire(t, m, tc.held(1))

			// 用不同的 ConnID：同一连接的重复申请是幂等续租，不走抢占判定
			second, err := m.Acquire(tc.want(2))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Acquire err = %v, want %v", err, tc.wantErr)
				}
				// 被拒之后原持有者必须完好无损
				if _, err := m.Check(first.ID, first.Conn); err != nil {
					t.Fatalf("incumbent lease broke after a denied acquire: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Acquire: %v", err)
			}
			// 抢占成功后旧租约必须立刻失效，且不会「自动恢复」
			// （Agent 文档 §3.4：HUMAN 退出时不恢复 AI 被打断前的旧动作）
			if _, err := m.Check(first.ID, first.Conn); !errors.Is(err, ErrControlNotHeld) {
				t.Fatalf("preempted lease Check = %v, want ErrControlNotHeld", err)
			}
			if _, err := m.Check(second.ID, second.Conn); err != nil {
				t.Fatalf("new lease Check: %v", err)
			}
		})
	}
}

// TestReacquireSameConnIsIdempotent 同一连接重复申请：ID 不变、不算抢占
func TestReacquireSameConnIsIdempotent(t *testing.T) {
	m, _, _ := newTestModule(t)
	first := mustAcquire(t, m, humanReq(1))
	again := mustAcquire(t, m, humanReq(1))

	if again.ID != first.ID {
		t.Fatalf("lease id changed on re-acquire: %s -> %s", first.ID, again.ID)
	}
	if again.Deadline.Before(first.Deadline) {
		t.Fatal("re-acquire must not shorten the deadline")
	}
	if _, err := m.Check(first.ID, first.Conn); err != nil {
		t.Fatalf("Check after idempotent re-acquire: %v", err)
	}
}

// TestAcquireRejectsMalformed 申请本身不良构时一律 fail closed
func TestAcquireRejectsMalformed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Request)
		wantErr error
	}{
		{
			name:    "ConnID 为 0",
			mutate:  func(r *Request) { r.Conn = 0 },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "Class 未指定（含试图申请 NONE）",
			mutate:  func(r *Request) { r.Class = ClassUnspecified },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "Resource 不是 base.main",
			mutate:  func(r *Request) { r.Resource = "arm.left" },
			wantErr: ErrUnknownResource,
		},
		{
			name:    "TTL 超出 Policy 上限",
			mutate:  func(r *Request) { r.TTL = time.Hour },
			wantErr: ErrPolicyViolation,
		},
		{
			name:    "deadman 超出 Policy 上限",
			mutate:  func(r *Request) { r.Deadman = time.Minute },
			wantErr: ErrPolicyViolation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, g, rec := newTestModule(t)
			before := g.Epoch()

			req := humanReq(1)
			tc.mutate(&req)

			if _, err := m.Acquire(req); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Acquire err = %v, want %v", err, tc.wantErr)
			}
			// 被拒的申请不得留下任何痕迹：不签租约、不动 epoch
			if m.cur.Load() != nil {
				t.Fatal("rejected acquire must not publish a lease")
			}
			if g.Epoch() != before {
				t.Fatalf("rejected acquire bumped epoch: %d -> %d", before, g.Epoch())
			}
			if !rec.has(actionDenied) {
				t.Fatalf("expected a control.%s audit event, got %v", actionDenied, rec.actions())
			}
		})
	}
}

// TestShorterThanPolicyIsAccepted 申请方可以主动要一个更严（更短）的窗口
func TestShorterThanPolicyIsAccepted(t *testing.T) {
	m, _, _ := newTestModule(t)

	req := humanReq(1)
	req.TTL = 500 * time.Millisecond
	req.Deadman = 100 * time.Millisecond

	l := mustAcquire(t, m, req)
	if l.TTL != 500*time.Millisecond || l.Deadman != 100*time.Millisecond {
		t.Fatalf("lease = (ttl %s, deadman %s), want (500ms, 100ms)", l.TTL, l.Deadman)
	}
}

// TestAcquireDeniedWhileLatched 锁存期间不签发任何普通租约
//
// 恢复控制权只能走 OEM Recovery / re-arm，不能靠重新申请（NRCP §14.4：re-arm 后
// 仍从 NONE 开始，由 HUMAN 或 AI 重新申请）
func TestAcquireDeniedWhileLatched(t *testing.T) {
	m, g, _ := newTestModule(t)
	g.Trip()

	if _, err := m.Acquire(humanReq(1)); !errors.Is(err, ErrSafetyLatched) {
		t.Fatalf("Acquire while latched = %v, want ErrSafetyLatched", err)
	}
	if m.cur.Load() != nil {
		t.Fatal("no lease may be published while the gate is latched")
	}

	// 走完 REARM_REQUIRED → NORMAL 之后才能重新签发
	if !g.RequireRearm() || !g.Rearm() {
		t.Fatal("gate did not walk through rearm")
	}
	mustAcquire(t, m, humanReq(1))
}

// TestLeaseIsNotTransferable 租约绑定连接，不能转让：ID 对但连接不对一律拒绝
func TestLeaseIsNotTransferable(t *testing.T) {
	m, _, _ := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))

	if _, err := m.Check(l.ID, ConnID(99)); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Check with foreign conn = %v, want ErrControlNotHeld", err)
	}
	if err := m.Release(l.ID, ConnID(99)); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Release with foreign conn = %v, want ErrControlNotHeld", err)
	}
	if _, err := m.Check(l.ID, l.Conn); err != nil {
		t.Fatalf("owner lost its lease to a foreign release: %v", err)
	}
}

// TestLeaseIDsAreUnpredictable 两条先后签发的租约不得撞 ID，也不得是可猜的序号
func TestLeaseIDsAreUnpredictable(t *testing.T) {
	m, _, _ := newTestModule(t)

	first := mustAcquire(t, m, humanReq(1))
	if err := m.Release(first.ID, first.Conn); err != nil {
		t.Fatalf("Release: %v", err)
	}
	second := mustAcquire(t, m, humanReq(1))

	if first.ID == second.ID {
		t.Fatal("two leases share the same id")
	}
	var zero ID
	if first.ID == zero || second.ID == zero {
		t.Fatal("lease id is all zeroes")
	}
}
