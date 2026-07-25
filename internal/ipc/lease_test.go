package ipc

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

// fakeLeases 是 ControlLeases 的测试替身。
//
// 不用真 control.Module：那需要 scheduler 的实时 Lane（要 CAP_SYS_NICE）与
// motiongate，把一个 wire 层测试变成一个内核装配测试。control 自己的状态机
// 已有 1000 行测试覆盖，这里只验 wire ↔ control 之间的翻译。
type fakeLeases struct {
	// mu 保护下面全部字段。
	//
	// 需要锁不是洁癖：RevokeConn 由每条连接自己的 serve goroutine 在收尾时调用，
	// 多条连接同时断开就是并发写。测试替身漏掉这层保护，-race 会把它报成
	// 生产代码的问题，白白浪费一轮排查。
	mu         sync.Mutex
	acquireErr error
	issued     []control.Request
	released   []control.ID
	revoked    []control.ConnID
	nextID     byte
}

func (f *fakeLeases) Acquire(req control.Request) (control.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquireErr != nil {
		return control.Lease{}, f.acquireErr
	}
	f.issued = append(f.issued, req)
	f.nextID++
	var id control.ID
	id[0] = f.nextID
	return control.Lease{
		ID:       id,
		Conn:     req.Conn,
		Class:    req.Class,
		Resource: req.Resource,
		Epoch:    42,
		Deadline: time.Now().Add(30 * time.Second),
	}, nil
}

func (f *fakeLeases) Release(id control.ID, _ control.ConnID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, id)
	return nil
}

func (f *fakeLeases) RevokeConn(conn control.ConnID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, conn)
}

// snapshot 读取断言需要的计数，全程持锁。
func (f *fakeLeases) counts() (issued, released, revoked int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issued), len(f.released), len(f.revoked)
}

// firstIssued 返回第一条申请的快照，没有则第二返回值为 false。
func (f *fakeLeases) firstIssued() (control.Request, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.issued) == 0 {
		return control.Request{}, false
	}
	return f.issued[0], true
}

// fakeResources 是 ResourceResolver 的测试替身。
type fakeResources struct{}

func (fakeResources) Resolve(typ, role string) (string, bool) {
	if typ == defaultResourceType && role == defaultResourceRole {
		return "base.main", true
	}
	if typ == "nervus.resource.manipulator.arm" && role == "main" {
		return "arm.main", true
	}
	return "", false
}

func newLeaseServer(t *testing.T, leases ControlLeases) (string, *fakeLeases) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "n.sock")
	fl, _ := leases.(*fakeLeases)
	s, err := New(Config{
		SockPath: sock,
		Log:      discardLog(),
		Auditor:  &fakeRecorder{},
		// 必须用 selfUIDInvariants：测试进程的 UID（开发机上通常是 1000）不在
		// 生产的 App 段 [20000,59999] 里，DefaultInvariants 会在 admit 阶段就
		// CheckUID 拒掉，表现是握手第一次写就 broken pipe。
		Invariants: selfUIDInvariants(t),
		Identity:   selfRegistry(t),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
		// 必须显式给 Limits：零值意味着 MaxConns/MaxConnsPerUID 都是 0，
		// 连接在 admit 阶段就被拒，表现是握手时「connection reset by peer」
		Limits:                   DefaultLimits(),
		Leases:                   leases,
		Resources:                fakeResources{},
		AllowUnverifiedComponent: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	})
	return sock, fl
}

func dialHandshaked(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	handshake(t, c)
	return c
}

func acquireEnv(reqID uint64, class ipcv1.ControllerClass, sel *ipcv1.ResourceSelector) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControl{AcquireControl: &ipcv1.AcquireControl{
		RequestId:       reqID,
		ControllerClass: class,
		Resource:        sel,
	}}}
}

func TestAcquireControl_Success(t *testing.T) {
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := readEnv(t, c).GetAcquireControlResult()
	if res == nil {
		t.Fatal("want AcquireControlResult")
	}
	if f := res.GetFailure(); f != nil {
		t.Fatalf("unexpected failure: %v", f.GetCode())
	}
	s := res.GetSuccess()
	if res.GetRequestId() != 1 {
		t.Errorf("request_id = %d, want 1（必须原样回带）", res.GetRequestId())
	}
	if s.GetLeaseId() == 0 {
		t.Error("lease_id 不能为 0：0 是保留值")
	}
	if s.GetMotionEpoch() != 42 {
		t.Errorf("motion_epoch = %d, want 42（Provider 靠它废止陈旧命令）", s.GetMotionEpoch())
	}
	if s.GetResourceHandle() != "base.main" {
		t.Errorf("resource_handle = %q", s.GetResourceHandle())
	}

	// 空 selector 必须落到协议规定的隐式默认，与 ResolveEndpoint 一致
	req, ok := fl.firstIssued()
	if !ok || req.Resource != "base.main" {
		t.Fatalf("issued = %+v，空 selector 应隐式取 base.main", req)
	}
	if req.Class != control.ClassHuman {
		t.Errorf("class = %v, want HUMAN", req.Class)
	}
	// Owner 必须是内核解析出的可信身份，不是客户端自报
	if req.Owner.PackageID == "" {
		t.Error("Owner 未填：审计归因会丢")
	}
}

func TestAcquireControl_ExplicitSelector(t *testing.T) {
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	sel := &ipcv1.ResourceSelector{Type: "nervus.resource.manipulator.arm", Role: "main"}
	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_AI, sel))); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := readEnv(t, c).GetAcquireControlResult()
	if res.GetSuccess().GetResourceHandle() != "arm.main" {
		t.Fatalf("resource_handle = %q, want arm.main", res.GetSuccess().GetResourceHandle())
	}
	if req, _ := fl.firstIssued(); req.Class != control.ClassAI {
		t.Errorf("class = %v, want AI", req.Class)
	}
}

func TestAcquireControl_UnknownResourceRejected(t *testing.T) {
	// 不认识的资源不该被签发租约——fail closed。
	sock, _ := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	sel := &ipcv1.ResourceSelector{Type: "nervus.resource.nonexistent", Role: "main"}
	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_AI, sel))); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil {
		t.Fatal("未知资源必须被拒绝")
	}
	assertLeaseReason(t, f, ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE)
}

func TestAcquireControl_UnspecifiedClassRejected(t *testing.T) {
	// 猜错 class 的后果是抢占矩阵用错优先级——把 AI 当人，或反过来。
	// 必须 fail closed，不替客户端猜。
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	env := acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_UNSPECIFIED, nil)
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil {
		t.Fatal("UNSPECIFIED class 必须被拒绝")
	}
	if f.GetCode() != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Errorf("code = %v, want INVALID_ARGUMENT", f.GetCode())
	}
	assertLeaseReason(t, f, ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_INVALID_CONTROLLER)
	if issued, _, _ := fl.counts(); issued != 0 {
		t.Error("被拒的申请不该到达 control")
	}
}

func TestAcquireControl_HeldByHumanCarriesDistinguishableReason(t *testing.T) {
	// envelope.proto 明说：调用者需要「被谁占着」这类可区分原因才知道该退避
	// 还是该抢占，笼统 BUSY 不够。
	sock, _ := newLeaseServer(t, &fakeLeases{acquireErr: control.ErrHeldByHuman})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_AI, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil {
		t.Fatal("want failure")
	}
	if f.GetCode() != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Errorf("code = %v, want FAILED_PRECONDITION", f.GetCode())
	}
	assertLeaseReason(t, f, ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_HELD_BY_HUMAN)
}

func TestAcquireControl_SafetyLatched(t *testing.T) {
	sock, _ := newLeaseServer(t, &fakeLeases{acquireErr: control.ErrSafetyLatched})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	assertLeaseReason(t, f, ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_SAFETY_LATCHED)
}

func TestReleaseControl_RoundTrip(t *testing.T) {
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write acquire: %v", err)
	}
	leaseID := readEnv(t, c).GetAcquireControlResult().GetSuccess().GetLeaseId()

	rel := &ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControl{ReleaseControl: &ipcv1.ReleaseControl{
		RequestId: 2, LeaseId: leaseID,
	}}}
	if err := WriteFrame(c, mustMarshal(t, rel)); err != nil {
		t.Fatalf("write release: %v", err)
	}
	res := readEnv(t, c).GetReleaseControlResult()
	if res.GetFailure() != nil {
		t.Fatalf("release failed: %v", res.GetFailure().GetCode())
	}
	if _, released, _ := fl.counts(); released != 1 {
		t.Fatalf("control.Release 调用了 %d 次, want 1", released)
	}
}

func TestReleaseControl_UnknownHandleDoesNotKillConnection(t *testing.T) {
	// 释放一个已过期/已被抢占的 lease_id 是正常时序（客户端还没收到撤销通知）。
	// 当协议违规处理会频繁踢掉正常客户端。
	sock, _ := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	rel := &ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControl{ReleaseControl: &ipcv1.ReleaseControl{
		RequestId: 1, LeaseId: 9999,
	}}}
	if err := WriteFrame(c, mustMarshal(t, rel)); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetReleaseControlResult().GetFailure()
	if f == nil || f.GetCode() != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("want FAILED_PRECONDITION, got %v", f)
	}

	// 连接必须还活着
	if err := WriteFrame(c, mustMarshal(t, pingEnv(7))); err != nil {
		t.Fatalf("连接已废: %v", err)
	}
	if readEnv(t, c).GetPong().GetNonce() != 7 {
		t.Fatal("连接在一次无效 release 之后不可用了")
	}
}

func TestLeaseHandles_AreConnectionScoped(t *testing.T) {
	// 查找键是 (连接, 句柄)。两条连接各自从 1 开始编号，A 的句柄在 B 上
	// 必须无效——否则一个 App 能释放另一个 App 的运动租约。
	sock, _ := newLeaseServer(t, &fakeLeases{})
	a := dialHandshaked(t, sock)
	b := dialHandshaked(t, sock)

	if err := WriteFrame(a, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	idA := readEnv(t, a).GetAcquireControlResult().GetSuccess().GetLeaseId()

	// b 从未申请过，a 的句柄在 b 上必须查不到
	rel := &ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControl{ReleaseControl: &ipcv1.ReleaseControl{
		RequestId: 1, LeaseId: idA,
	}}}
	if err := WriteFrame(b, mustMarshal(t, rel)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if readEnv(t, b).GetReleaseControlResult().GetFailure() == nil {
		t.Fatal("跨连接释放必须失败：查找键是 (连接, 句柄)")
	}
}

func TestConnClose_RevokesLeases(t *testing.T) {
	// 租约绑连接、断开即失效。不撤的话，一个断了线的 App 仍然「持有」执行器
	// 控制权，谁也抢不走，直到 TTL 自然到期。
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	handshake(t, c)
	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	readEnv(t, c)
	_ = c.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, revoked := fl.counts(); revoked > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("连接关闭后未撤销该连接名下的租约")
}

func TestAcquireControl_ResultFromPeerIsProtocolViolation(t *testing.T) {
	// AcquireControlResult 是 nervud → 对端方向。对端发来它说明状态机错乱
	// 或对方不是合法客户端，必须关连接。
	sock, _ := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	bad := &ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControlResult{
		AcquireControlResult: &ipcv1.AcquireControlResult{RequestId: 1},
	}}
	if err := WriteFrame(c, mustMarshal(t, bad)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
}

func TestLeasesNil_ReturnsUnavailableNotClose(t *testing.T) {
	// control 未接线是能力缺口不是协议违规：回 UNAVAILABLE，不关连接。
	sock, _ := newLeaseServer(t, nil)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil || f.GetCode() != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("want UNAVAILABLE, got %v", f)
	}
	// 连接仍可用
	if err := WriteFrame(c, mustMarshal(t, pingEnv(3))); err != nil {
		t.Fatalf("连接已废: %v", err)
	}
	if readEnv(t, c).GetPong().GetNonce() != 3 {
		t.Fatal("connection unusable")
	}
}

func assertLeaseReason(t *testing.T, f *ipcv1.Failure, want ipcv1.ControlLeaseErrorReason) {
	t.Helper()
	if f == nil {
		t.Fatal("want failure")
	}
	var d ipcv1.ControlLeaseErrorDetail
	if err := proto.Unmarshal(f.GetErrorDetail(), &d); err != nil {
		t.Fatalf("decode ControlLeaseErrorDetail: %v", err)
	}
	if d.GetReason() != want {
		t.Errorf("reason = %v, want %v", d.GetReason(), want)
	}
}

var _ = errors.Is
var _ identity.Caller
