package operation

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
)

// 状态码短别名，让断言读起来更紧凑。
const (
	acceptedCode  = ipcv1.StatusCode_STATUS_CODE_ACCEPTED
	okCode        = ipcv1.StatusCode_STATUS_CODE_OK
	notFoundCode  = ipcv1.StatusCode_STATUS_CODE_NOT_FOUND
	invalidCode   = ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	preconCode    = ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION
	cancelledCode = ipcv1.StatusCode_STATUS_CODE_CANCELLED
	deadlineCode  = ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED
	internalCode  = ipcv1.StatusCode_STATUS_CODE_INTERNAL
)

// --- fake 依赖 -----------------------------------------------------------

// fakeAuditor 记录全部审计事件，供断言"非法转移/拒绝/终结都记一条"。
type fakeAuditor struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAuditor) Record(_ context.Context, ev audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeAuditor) count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, ev := range f.events {
		if ev.Action == "operation."+action {
			n++
		}
	}
	return n
}

func (f *fakeAuditor) has(action string) bool { return f.count(action) > 0 }

// fakeResource 是 ResourceValidator 的测试实现。
type fakeResource struct{ valid map[string]bool }

func (f fakeResource) Valid(h string) bool { return f.valid[h] }

// fakeLease 是 LeaseValidator 的测试实现。ok 决定是否接受；calls 记录被问过的参数。
type fakeLease struct {
	ok bool
}

func (f fakeLease) ValidLease(_, _ uint64, _ string) bool { return f.ok }

// clock 是可控时钟，供 deadline/超时测试确定性推进。
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// --- 构造 ---------------------------------------------------------------

const testResource = "arm.main"

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testCaller() identity.Caller {
	return identity.Caller{PackageID: "com.test.app", Trust: identity.TrustOrdinary, UID: 20001}
}

func otherCaller() identity.Caller {
	return identity.Caller{PackageID: "com.other.app", Trust: identity.TrustOrdinary, UID: 20002}
}

func systemCaller() identity.Caller { return identity.Caller{} } // 空 PackageID = kernel

// newTestManager 构造一个带可控时钟、接受 arm.main 资源、接受 lease 的 Manager。
// 不启动后台 goroutine：需要 deadline/收敛的测试直接调 scanDeadlines/convergeSupersede。
func newTestManager(t *testing.T, leaseOK bool) (*Manager, *fakeAuditor, *clock) {
	t.Helper()
	aud := &fakeAuditor{}
	clk := &clock{t: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)}
	m := New(
		fakeResource{valid: map[string]bool{testResource: true}},
		fakeLease{ok: leaseOK},
		aud,
		discardLog(),
	)
	m.now = clk.now
	return m, aud, clk
}

func testOrigin() OriginBinding {
	return OriginBinding{
		InterfaceID: "nervus.manipulator",
		IfaceMajor:  1,
		MethodID:    7,
		SchemaHash:  []byte{0xde, 0xad},
	}
}

// createMotion 创建一个运动类 operation（leaseID != 0）并断言 ACCEPTED。
func createMotion(t *testing.T, m *Manager, conn ConnHandle, caller identity.Caller, epoch uint64) uint64 {
	t.Helper()
	deadline := m.now().Add(time.Minute)
	id, code := m.Create(conn, caller, testOrigin(), []string{testResource}, 42, epoch, deadline)
	if code != acceptedCode {
		t.Fatalf("Create motion: code=%v, want ACCEPTED", code)
	}
	if id == 0 {
		t.Fatal("Create motion: id=0")
	}
	return id
}
