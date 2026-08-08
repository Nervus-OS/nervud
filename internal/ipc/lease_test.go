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

//

type fakeLeases struct {

	//

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

func (f *fakeLeases) CheckLease(id control.ID, conn control.ConnID) (control.LeaseProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checkErr != nil {
		return control.LeaseProof{}, f.checkErr
	}
	for _, lease := range f.active {
		if lease.ID != id || lease.Conn != conn {
			continue
		}
		return control.LeaseProof{
			ID:                 lease.ID,
			Class:              lease.Class,
			Resource:           lease.Resource,
			ResourceGeneration: lease.ResourceGeneration,
			Deadline:           lease.Deadline,
			Epoch:              lease.Epoch,
		}, nil
	}
	return control.LeaseProof{}, control.ErrControlNotHeld
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

func (f *fakeLeases) counts() (issued, released, revoked int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issued), len(f.released), len(f.revoked)
}

func (f *fakeLeases) firstIssued() (control.Request, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.issued) == 0 {
		return control.Request{}, false
	}
	return f.issued[0], true
}

const (
	testResourceTypeBase = "nervus.resource.motion.base"
	testResourceRoleMain = "main"
)

type fakeResources struct{}

func (fakeResources) ResolveControl(typ, role string) (string, uint64, bool) {
	if typ == testResourceTypeBase && role == testResourceRoleMain {
		return "base.main", 11, true
	}
	if typ == "nervus.resource.manipulator.arm" && role == "main" {
		return "arm.main", 12, true
	}
	return "", 0, false
}

func (f fakeResources) ResolveControlBySelector(sel *ipcv1.ResourceSelector) (string, uint64, bool) {
	return f.ResolveControl(sel.GetType(), sel.GetRole())
}

type mutableResources struct {
	mu         sync.Mutex
	generation uint64
}

func (r *mutableResources) ResolveControl(typ, role string) (string, uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if typ != testResourceTypeBase || role != testResourceRoleMain || r.generation == 0 {
		return "", 0, false
	}
	return "base.main", r.generation, true
}

func (r *mutableResources) ResolveControlBySelector(sel *ipcv1.ResourceSelector) (string, uint64, bool) {
	return r.ResolveControl(sel.GetType(), sel.GetRole())
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

		Invariants: selfUIDInvariants(t),
		Identity:   selfRegistry(t),
		Permission: permission.NewDefaultRegistry(),

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

//

//

func acquireEnv(reqID uint64, class ipcv1.ControllerClass, sel *ipcv1.ResourceSelector) *ipcv1.Envelope {
	if sel == nil {
		sel = &ipcv1.ResourceSelector{
			Type: testResourceTypeBase, Role: testResourceRoleMain,
		}
	}
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControl{AcquireControl: &ipcv1.AcquireControl{
		RequestId:       reqID,
		ControllerClass: class,
		Resource:        sel,
	}}}
}

//

func TestAcquireControl_EmptySelectorRejected(t *testing.T) {
	sock, _ := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	env := &ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControl{
		AcquireControl: &ipcv1.AcquireControl{
			RequestId:       1,
			ControllerClass: ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN,
		},
	}}
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := readEnv(t, c).GetAcquireControlResult()
	if res == nil {
		t.Fatal("want AcquireControlResult")
	}
	if res.GetSuccess() != nil {
		t.Fatal("unexpected ipc result; selector")
	}
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("code = %v, want FAILED_PRECONDITION", code)
	}
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
		t.Errorf("unexpected ipc result; request_id = %d, want 1", res.GetRequestId())
	}
	if s.GetLeaseId() == 0 {
		t.Error("unexpected ipc result; lease_id 0 0")
	}
	if s.GetMotionEpoch() != 42 {
		t.Errorf("unexpected ipc result; motion_epoch = %d, want 42 Provider", s.GetMotionEpoch())
	}
	if s.GetResourceHandle() != "base.main" {
		t.Errorf("resource_handle = %q", s.GetResourceHandle())
	}
	if got := s.GetDeadlineNanos(); got < int64(39*time.Second) || got > int64(41*time.Second) {
		t.Errorf("deadline_nanos = %d, want CLOCK_MONOTONIC absolute value near 40s", got)
	}

	req, ok := fl.firstIssued()
	if !ok || req.Resource != "base.main" || req.ResourceGeneration != 11 {
		t.Fatalf("unexpected ipc result; issued = %+v selector base.main", req)
	}
	if req.Class != control.ClassHuman {
		t.Errorf("class = %v, want HUMAN", req.Class)
	}

	if req.Owner.PackageID == "" {
		t.Error("unexpected ipc result; Owner")
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

	sock, _ := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	sel := &ipcv1.ResourceSelector{Type: "nervus.resource.nonexistent", Role: "main"}
	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_AI, sel))); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil {
		t.Fatal("unexpected ipc result")
	}
	assertLeaseReason(t, f, ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE)
}

func TestAcquireControl_UnspecifiedClassRejected(t *testing.T) {

	sock, fl := newLeaseServer(t, &fakeLeases{})
	c := dialHandshaked(t, sock)

	env := acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_UNSPECIFIED, nil)
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil {
		t.Fatal("unexpected ipc result; UNSPECIFIED class")
	}
	if f.GetCode() != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Errorf("code = %v, want INVALID_ARGUMENT", f.GetCode())
	}
	assertLeaseReason(t, f, ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_INVALID_CONTROLLER)
	if issued, _, _ := fl.counts(); issued != 0 {
		t.Error("unexpected ipc result; control")
	}
}

func TestAcquireControl_HeldByHumanCarriesDistinguishableReason(t *testing.T) {

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
		t.Fatalf("unexpected ipc result; control.Release %d, want 1", released)
	}
}

func TestReleaseControl_UnknownHandleDoesNotKillConnection(t *testing.T) {

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

	if err := WriteFrame(c, mustMarshal(t, pingEnv(7))); err != nil {
		t.Fatalf("unexpected ipc result; value = %v", err)
	}
	if readEnv(t, c).GetPong().GetNonce() != 7 {
		t.Fatal("unexpected ipc result; release")
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

	sock, _ := newLeaseServer(t, &fakeLeases{})
	a := dialHandshaked(t, sock)
	b := dialHandshaked(t, sock)

	if err := WriteFrame(a, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	idA := readEnv(t, a).GetAcquireControlResult().GetSuccess().GetLeaseId()

	rel := &ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControl{ReleaseControl: &ipcv1.ReleaseControl{
		RequestId: 1, LeaseId: idA,
	}}}
	if err := WriteFrame(b, mustMarshal(t, rel)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if readEnv(t, b).GetReleaseControlResult().GetFailure() == nil {
		t.Fatal("unexpected ipc result; (, )")
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
	t.Fatal("unexpected ipc result")
}

func TestAcquireControl_ResultFromPeerIsProtocolViolation(t *testing.T) {

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

	sock, _ := newLeaseServer(t, nil)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, acquireEnv(1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil))); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := readEnv(t, c).GetAcquireControlResult().GetFailure()
	if f == nil || f.GetCode() != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("want UNAVAILABLE, got %v", f)
	}

	if err := WriteFrame(c, mustMarshal(t, pingEnv(3))); err != nil {
		t.Fatalf("unexpected ipc result; value = %v", err)
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
