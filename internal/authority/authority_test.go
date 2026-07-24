package authority

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/nervus-os/nervud/internal/audit"
)

type fakeRecorder struct{ events []audit.Event }

func (f *fakeRecorder) Record(_ context.Context, ev audit.Event) { f.events = append(f.events, ev) }

func newTestGate(t *testing.T) (*Gate, *fakeRecorder) {
	t.Helper()
	rec := &fakeRecorder{}
	g, err := New(Config{
		Auditor: rec,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, rec
}

func validReq() CreateDataDirRequest {
	return CreateDataDirRequest{
		Path: "/var/lib/nervus/package-data/com.example.app",
		UID:  20001, GID: 20001, Perm: 0o700,
	}
}

func TestNew_RequiresAuditorAndLog(t *testing.T) {
	if _, err := New(Config{Log: slog.Default()}); err == nil {
		t.Fatal("want error when Auditor is nil")
	}
	if _, err := New(Config{Auditor: &fakeRecorder{}}); err == nil {
		t.Fatal("want error when Log is nil")
	}
}

func TestDo_InvariantDenied_NotExecutedButAudited(t *testing.T) {
	g, rec := newTestGate(t)
	executed := false

	req := validReq()
	req.UID = 0
	_, err := do(context.Background(), g, SubjectKernel(), req,
		func(context.Context, CreateDataDirRequest) (DirHandle, error) {
			executed = true
			return DirHandle{}, nil
		})

	if !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("want ErrInvariantViolated, got %v", err)
	}
	if executed {
		t.Fatal("run must not execute when invariant is violated")
	}
	if len(rec.events) != 1 || !rec.events[0].Denied {
		t.Fatalf("want exactly one Denied audit event, got %+v", rec.events)
	}
	if rec.events[0].Detail != req.Path {
		t.Fatalf("audit detail = %q, want request path", rec.events[0].Detail)
	}
}

func TestDo_SuccessIsAudited(t *testing.T) {
	g, rec := newTestGate(t)

	res, err := do(context.Background(), g, Subject{PackageID: "com.example.app", UID: 20001},
		validReq(),
		func(_ context.Context, r CreateDataDirRequest) (DirHandle, error) {
			return DirHandle{Path: r.Path}, nil
		})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if res.Path != validReq().Path {
		t.Fatalf("result path = %q", res.Path)
	}

	if len(rec.events) != 1 {
		t.Fatalf("want exactly one audit event, got %d", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Denied || ev.Err != nil {
		t.Fatalf("success event polluted: %+v", ev)
	}
	if ev.Action != "CreatePrivateDataDirectory" {
		t.Fatalf("action = %q", ev.Action)
	}
	if ev.Subject != "pkg:com.example.app uid:20001" {
		t.Fatalf("subject = %q", ev.Subject)
	}
}

func TestDo_ExecutionFailureIsAudited(t *testing.T) {
	g, rec := newTestGate(t)
	boom := errors.New("boom")

	_, err := do(context.Background(), g, SubjectKernel(), validReq(),
		func(context.Context, CreateDataDirRequest) (DirHandle, error) {
			return DirHandle{}, boom
		})
	if !errors.Is(err, boom) {
		t.Fatalf("want wrapped boom, got %v", err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("want exactly one audit event, got %d", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Denied {
		t.Fatal("execution failure is not a denial")
	}
	if !errors.Is(ev.Err, boom) {
		t.Fatalf("audit must carry the execution error, got %v", ev.Err)
	}
}

func TestCheckContained(t *testing.T) {
	inv := DefaultInvariants()
	cases := []struct {
		name string
		path string
		ok   bool
	}{
		{"direct child", "/var/lib/nervus/package-data/app", true},
		{"nested", "/var/lib/nervus/package-data/app/cache", true},
		{"root itself", "/var/lib/nervus/package-data", false},
		{"prefix trick", "/var/lib/nervus/package-data-evil/x", false},
		{"dotdot escape", "/var/lib/nervus/package-data/../../../etc/shadow", false},
		{"dotdot inside", "/var/lib/nervus/package-data/app/../app2", true},
		{"relative", "var/lib/nervus/package-data/app", false},
		{"unrelated", "/etc/passwd", false},
	}
	for _, c := range cases {
		err := inv.CheckContained(c.path, inv.DataRoot)
		if got := err == nil; got != c.ok {
			t.Errorf("%s: CheckContained(%q) err=%v, want ok=%v", c.name, c.path, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrInvariantViolated) {
			t.Errorf("%s: error must wrap ErrInvariantViolated, got %v", c.name, err)
		}
	}
}

func TestCheckUID(t *testing.T) {
	inv := DefaultInvariants()
	cases := []struct {
		uid uint32
		ok  bool
	}{
		{0, false}, {1, false}, {19999, false},
		{20000, true}, {40000, true}, {59999, true},
		{60000, false},
	}
	for _, c := range cases {
		if err := inv.CheckUID(c.uid); (err == nil) != c.ok {
			t.Errorf("CheckUID(%d) err=%v, want ok=%v", c.uid, err, c.ok)
		}
	}
}

func TestCreateDataDirRequest_RejectsExposedPerm(t *testing.T) {
	req := validReq()
	req.Perm = 0o755
	if err := req.Validate(DefaultInvariants()); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("want ErrInvariantViolated, got %v", err)
	}
}

func TestRebootRequest_RequiresReason(t *testing.T) {
	if err := (RebootRequest{}).Validate(nil); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("want ErrInvariantViolated, got %v", err)
	}
	if err := (RebootRequest{Reason: "system update commit"}).Validate(nil); err != nil {
		t.Fatalf("valid reboot rejected: %v", err)
	}
}

func TestInstallVerifiedPackageRequest_Validate(t *testing.T) {
	inv := DefaultInvariants()

	valid := InstallVerifiedPackageRequest{
		StagingDir: "/var/lib/nervus/pkgmanagerd/staging/tx-1",
		DestDir:    inv.PackageRoot + "/com.example.app/1.0.0",
	}
	if err := valid.Validate(inv); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	outside := valid
	outside.DestDir = "/etc/passwd"
	if err := outside.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("dest outside PackageRoot: err = %v, want ErrInvariantViolated", err)
	}

	noStaging := valid
	noStaging.StagingDir = ""
	if err := noStaging.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("empty staging dir: err = %v, want ErrInvariantViolated", err)
	}
}
