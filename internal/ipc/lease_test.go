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

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

type fakeLeaseKey struct {
	conn     control.ConnID
	resource string
}

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
	resources  []catalog.RevokedResource
	checkErr   error
	checked    []struct {
		conn       control.ConnID
		resource   string
		generation uint64
	}
	nextID byte
	active map[fakeLeaseKey]control.Lease
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
	lease := control.Lease{
		ID:                 id,
		Conn:               req.Conn,
		Class:              req.Class,
		Resource:           req.Resource,
		ResourceGeneration: req.ResourceGeneration,
		Epoch:              42,
		Deadline:           time.Now().Add(30 * time.Second),
	}
	if f.active == nil {
		f.active = make(map[fakeLeaseKey]control.Lease)
	}
	f.active[fakeLeaseKey{conn: req.Conn, resource: req.Resource}] = lease
	return lease, nil
}

func (f *fakeLeases) Release(id control.ID, conn control.ConnID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, id)
	for key, lease := range f.active {
		if key.conn == conn && lease.ID == id {
			delete(f.active, key)
		}
	}
	return nil
}

func (f *fakeLeases) CheckResource(
	conn control.ConnID,
	resource string,
	generation uint64,
) (control.LeaseProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, struct {
		conn       control.ConnID
		resource   string
		generation uint64
	}{conn: conn, resource: resource, generation: generation})
	if f.checkErr != nil {
		return control.LeaseProof{}, f.checkErr
	}
	lease, ok := f.active[fakeLeaseKey{conn: conn, resource: resource}]
	if ok && lease.ResourceGeneration == generation {
		return control.LeaseProof{
			ID:                 lease.ID,
			Class:              lease.Class,
			Resource:           lease.Resource,
			ResourceGeneration: lease.ResourceGeneration,
			Deadline:           lease.Deadline,
			Epoch:              lease.Epoch,
		}, nil
	}
	return control.LeaseProof{
		Resource:           resource,
		ResourceGeneration: generation,
		Deadline:           time.Now().Add(30 * time.Second),
		Epoch:              42,
	}, nil
}

func (f *fakeLeases) RevokeConn(conn control.ConnID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, conn)
	for key := range f.active {
		if key.conn == conn {
			delete(f.active, key)
		}
	}
}

func (f *fakeLeases) RevokeResource(resource string, generation uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resources = append(f.resources, catalog.RevokedResource{
		Handle: resource, Generation: generation,
	})
	for key, lease := range f.active {
		if key.resource == resource && lease.ResourceGeneration == generation {
			delete(f.active, key)
		}
	}
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

func (fakeResources) ResolveControl(typ, role string) (string, uint64, bool) {
	if typ == defaultResourceType && role == defaultResourceRole {
		return "base.main", 11, true
	}
	if typ == "nervus.resource.manipulator.arm" && role == "main" {
		return "arm.main", 12, true
	}
	return "", 0, false
}

type mutableResources struct {
	mu         sync.Mutex
	generation uint64
}

func (r *mutableResources) ResolveControl(typ, role string) (string, uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if typ != defaultResourceType || role != defaultResourceRole || r.generation == 0 {
		return "", 0, false
	}
	return "base.main", r.generation, true
}

func (r *mutableResources) setGeneration(generation uint64) {
	r.mu.Lock()
	r.generation = generation
	r.mu.Unlock()
}

type blockingAcquireLeases struct {
	*fakeLeases
	entered chan<- struct{}
	resume  <-chan struct{}
}

func (l *blockingAcquireLeases) Acquire(req control.Request) (control.Lease, error) {
	l.entered <- struct{}{}
	<-l.resume
	return l.fakeLeases.Acquire(req)
}

func newLeaseServer(t *testing.T, leases ControlLeases) (string, *fakeLeases) {
	return newLeaseServerWithResources(t, leases, fakeResources{})
}

func newLeaseServerWithResources(
	t *testing.T,
	leases ControlLeases,
	resources ResourceResolver,
) (string, *fakeLeases) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "n.sock")
	fl, _ := leases.(*fakeLeases)
	if blocking, ok := leases.(*blockingAcquireLeases); ok {
		fl = blocking.fakeLeases
	}
	s, err := New(Config{
		SockPath: sock,
		Log:      discardLog(),
		Auditor:  &fakeRecorder{},
		// 必须用 selfUIDInvariants：测试进程的 UID（开发机上通常是 1000）不在
		// 生产的 App 段 [20000,59999] 里，DefaultInvariants 会在 admit 阶段就
		// CheckUID 拒掉，表现是握手第一次写就 broken pipe。
		Invariants: selfUIDInvariants(t),
		Identity:   selfRegistry(t),
		Permission: permission.NewDefaultRegistry(),
		// 必须显式给 Limits：零值意味着 MaxConns/MaxConnsPerUID 都是 0，
		// 连接在 admit 阶段就被拒，表现是握手时「connection reset by peer」
		Limits:    DefaultLimits(),
		Leases:    leases,
		Resources: resources,
		Transfer:  newTestTransfer(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.monotonicNow = func() (uint64, error) { return uint64(10 * time.Second), nil }
	installTestComponentVerifier(s)
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
	if got := s.GetDeadlineNanos(); got < int64(39*time.Second) || got > int64(41*time.Second) {
		t.Errorf("deadline_nanos = %d, want CLOCK_MONOTONIC absolute value near 40s", got)
	}

	// 空 selector 必须落到协议规定的隐式默认，与 ResolveEndpoint 一致
	req, ok := fl.firstIssued()
	if !ok || req.Resource != "base.main" || req.ResourceGeneration != 11 {
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
	if req, _ := fl.firstIssued(); req.Class != control.ClassAI || req.ResourceGeneration != 12 {
		t.Errorf("request = %+v, want AI on resource generation 12", req)
	}
}

func TestAcquireControl_RejectsGenerationPublishedDuringAcquire(t *testing.T) {
	entered := make(chan struct{}, 1)
	resume := make(chan struct{})
	fl := &fakeLeases{}
	resources := &mutableResources{generation: 11}
	sock, _ := newLeaseServerWithResources(t, &blockingAcquireLeases{
		fakeLeases: fl,
		entered:    entered,
		resume:     resume,
	}, resources)
	c := dialHandshaked(t, sock)

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- WriteFrame(c, mustMarshal(t, acquireEnv(
			1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil)))
	}()
	<-entered
	resources.setGeneration(12)
	close(resume)
	if err := <-writeDone; err != nil {
		t.Fatalf("write: %v", err)
	}

	failure := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if failure == nil || failure.GetCode() != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("generation race result = %v, want FAILED_PRECONDITION", failure)
	}
	assertLeaseReason(t, failure,
		ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE)
	issued, released, _ := fl.counts()
	if issued != 1 || released != 1 {
		t.Fatalf("generation race issued/released = %d/%d, want 1/1", issued, released)
	}
}

func TestAcquireControl_ClassChoiceIsAuditedAsSelfReported(t *testing.T) {
	recorder := &fakeRecorder{}
	server := &Server{auditor: recorder}
	server.auditLeaseClass(
		identity.Caller{PackageID: "com.example.agent"},
		control.ClassHuman,
		"base.main",
	)

	events := recorder.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	event := events[0]
	if event.Action != "ipc.AcquireControl.classSelfReported" ||
		event.Subject != "com.example.agent" ||
		event.Detail != "class=HUMAN resource=base.main" {
		t.Fatalf("self-reported class audit = %+v", event)
	}
}

func TestAcquireControl_RequestedDeadlineBecomesRequestedTTL(t *testing.T) {
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	env := acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil)
	env.GetAcquireControl().RequestedDeadlineNanos = int64(125 * time.Millisecond)
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if failure := readEnv(t, c).GetAcquireControlResult().GetFailure(); failure != nil {
		t.Fatalf("unexpected failure: %v", failure.GetCode())
	}

	req, ok := fl.firstIssued()
	if !ok {
		t.Fatal("request did not reach control module")
	}
	if req.RequestedTTL != 125*time.Millisecond {
		t.Fatalf("RequestedTTL = %s, want 125ms", req.RequestedTTL)
	}
	if req.TTL != 0 {
		t.Fatalf("strict TTL = %s, want zero for a wire preference", req.TTL)
	}
}

func TestAcquireControl_ZeroRequestIDClosesConnection(t *testing.T) {
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(0, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
	if issued, _, _ := fl.counts(); issued != 0 {
		t.Fatalf("control received %d requests after protocol violation, want 0", issued)
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

func TestReleaseControl_ZeroRequestIDClosesConnection(t *testing.T) {
	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write acquire: %v", err)
	}
	leaseID := readEnv(t, c).GetAcquireControlResult().GetSuccess().GetLeaseId()
	rel := &ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControl{ReleaseControl: &ipcv1.ReleaseControl{
		LeaseId: leaseID,
	}}}
	if err := WriteFrame(c, mustMarshal(t, rel)); err != nil {
		t.Fatalf("write release: %v", err)
	}
	expectClosed(t, c)
	if _, released, _ := fl.counts(); released != 0 {
		t.Fatalf("control.Release called %d times after protocol violation, want 0", released)
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

func TestLeaseHandles_StayStableAcrossRenewalAndAreNeverReused(t *testing.T) {
	co := &conn{}
	var id control.ID
	id[0] = 7

	first := co.registerLease(control.Lease{ID: id})
	renewed := co.registerLease(control.Lease{ID: id})
	if renewed != first {
		t.Fatalf("renewed lease_id = %d, want stable %d", renewed, first)
	}
	if len(co.leases) != 1 || len(co.leaseHandles) != 1 {
		t.Fatalf("renewal grew handle maps: forward=%d reverse=%d",
			len(co.leases), len(co.leaseHandles))
	}

	co.forgetLease(first)
	reissued := co.registerLease(control.Lease{ID: id})
	if reissued == first || reissued == 0 {
		t.Fatalf("reissued lease_id = %d, must be new and non-zero (old %d)",
			reissued, first)
	}
}

func TestControlLeaseEnded_ForgetsOnlyExactWireHandle(t *testing.T) {
	co := &conn{connID: 41}
	var endedID, replacementID control.ID
	endedID[0] = 7
	replacementID[0] = 8
	endedHandle := co.registerLease(control.Lease{ID: endedID})
	replacementHandle := co.registerLease(control.Lease{ID: replacementID})

	s := &Server{
		controlConns: map[control.ConnID]*conn{co.connID: co},
		dispatch:     newDispatchTable(),
		transfer:     newTestTransfer(t),
	}
	s.ControlLeaseEnded(co.connID, "base.main", endedID)
	s.ControlLeaseEnded(co.connID, "base.main", endedID)

	if _, ok := co.lookupLease(endedHandle); ok {
		t.Fatal("ended lease wire handle is still registered")
	}
	if got, ok := co.lookupLease(replacementHandle); !ok || got != replacementID {
		t.Fatalf("replacement wire handle = %v, ok=%v; want exact replacement lease", got, ok)
	}
	co.leaseMu.Lock()
	forward, reverse := len(co.leases), len(co.leaseHandles)
	co.leaseMu.Unlock()
	if forward != 1 || reverse != 1 {
		t.Fatalf("wire handle maps after terminal cleanup: forward=%d reverse=%d, want 1/1",
			forward, reverse)
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
