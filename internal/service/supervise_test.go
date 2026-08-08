package service

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

func jvmAppFixture(t *testing.T) (*Manager, pkgregistry.Entry, pkgregistry.Component) {
	t.Helper()
	m := &Manager{inv: authority.DefaultInvariants()}
	e := pkgregistry.Entry{
		Manifest: pkgregistry.Manifest{
			PackageID: "com.example.app",
			Components: []pkgregistry.Component{{
				ID: "main", Type: pkgregistry.ComponentApp,
				Runtime: pkgregistry.RuntimeJVM, Entry: "lib/main.jar",
				LaunchMode: pkgregistry.LaunchManual,
			}},
		},
		ActiveVersion: "1.0.0",
		UID:           20001,
		Source:        pkgregistry.SourceDynamicInstall,
	}
	return m, e, e.Manifest.Components[0]
}

func TestCodeDir_DiffersBySource(t *testing.T) {

	//

	inv := authority.DefaultInvariants()

	sys := pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: "nervus.pkgmanagerd"},
		ActiveVersion: "0.1.0",
		Source:        pkgregistry.SourceSystemImage,
	}
	got := codeDir(inv, sys)
	want := "/usr/lib/nervus/system-packages/nervus.pkgmanagerd"
	if got != want {
		t.Errorf("unexpected service result; codeDir = %q, want %q", got, want)
	}

	dyn := pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: "com.example.app"},
		ActiveVersion: "1.2.3",
		Source:        pkgregistry.SourceDynamicInstall,
	}
	got = codeDir(inv, dyn)
	want = "/var/lib/nervus/packages/com.example.app/1.2.3"
	if got != want {
		t.Errorf("unexpected service result; codeDir = %q, want %q", got, want)
	}
}

func TestCodeDir_SystemPathPassesInvariantCheck(t *testing.T) {

	inv := authority.DefaultInvariants()
	sys := pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: "nervus.pkgmanagerd"},
		ActiveVersion: "0.1.0",
		Source:        pkgregistry.SourceSystemImage,
	}
	exec := filepath.Join(codeDir(inv, sys), "bin/pkgmanagerd")
	if err := inv.CheckContainedInCodeRoot(exec); err != nil {
		t.Fatalf("unexpected service result; value = %v", err)
	}

	if err := inv.CheckContainedInCodeRoot("/etc/shadow"); err == nil {
		t.Error("unexpected service result; /etc/shadow")
	}
}

//

func TestBuildStartReq_JVMGetsWritableTmpAndHome(t *testing.T) {
	m, e, c := jvmAppFixture(t)
	req, err := m.buildStartReq(e, c, "nervus-com.example.app-main.service")
	if err != nil {
		t.Fatalf("buildStartReq: %v", err)
	}

	dataDir := filepath.Join(m.inv.DataRoot, e.Manifest.PackageID)
	wantTmp := "-Djava.io.tmpdir=" + dataDir
	wantHome := "-Duser.home=" + dataDir

	if !slices.Contains(req.Args, wantTmp) {
		t.Errorf("unexpected service result; value = %q args=%v", wantTmp, req.Args)
	}
	if !slices.Contains(req.Args, wantHome) {
		t.Errorf("unexpected service result; value = %q args=%v", wantHome, req.Args)
	}

	if !slices.Contains(req.ReadWritePaths, dataDir) {
		t.Errorf("unexpected service result; java.io.tmpdir %q ReadWritePaths=%v", dataDir, req.ReadWritePaths)
	}

	tmpIdx := slices.Index(req.Args, wantTmp)
	jarIdx := slices.Index(req.Args, "-jar")
	if jarIdx >= 0 && tmpIdx > jarIdx {
		t.Errorf("unexpected service result; D -jar args=%v", req.Args)
	}
}
