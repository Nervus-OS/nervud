package systemd

import (
	"errors"
	"testing"
)

func propMap(t *testing.T, spec UnitSpec) map[string]any {
	t.Helper()
	props, err := BuildProperties(spec)
	if err != nil {
		t.Fatalf("BuildProperties: %v", err)
	}
	m := make(map[string]any, len(props))
	for _, p := range props {
		m[p.Name] = p.Value.Value()
	}
	return m
}

func validSpec() UnitSpec {
	return UnitSpec{
		Name:       "nervus-com.example.app-main.service",
		ExecPath:   "/var/lib/nervus/packages/com.example.app/1.0.0/bin",
		WorkingDir: "/var/lib/nervus/package-data/com.example.app",
		UID:        20001, GID: 20001,
	}
}

func TestBuildProperties_CoreSandboxAlwaysOn(t *testing.T) {
	m := propMap(t, validSpec())

	for _, name := range []string{
		"NoNewPrivileges", "ProtectSystem", "PrivateTmp", "PrivateDevices",
		"DevicePolicy", "ProtectKernelTunables", "ProtectKernelModules",
		"RestrictSUIDSGID", "SystemCallFilter", "RestrictAddressFamilies", "ExecStart",
	} {
		if _, ok := m[name]; !ok {
			t.Errorf("missing mandatory property %q", name)
		}
	}
	if m["NoNewPrivileges"] != true {
		t.Errorf("NoNewPrivileges = %v, want true", m["NoNewPrivileges"])
	}
	if m["ProtectSystem"] != "strict" {
		t.Errorf("ProtectSystem = %v, want strict", m["ProtectSystem"])
	}
	if m["User"] != "20001" || m["Group"] != "20001" {
		t.Errorf("User/Group = %v/%v, want 20001/20001", m["User"], m["Group"])
	}
}

func TestBuildProperties_SystemCallFilterIsWhitelist(t *testing.T) {
	m := propMap(t, validSpec())
	rs, ok := m["SystemCallFilter"].(restrictSet)
	if !ok {
		t.Fatalf("SystemCallFilter type = %T, want restrictSet", m["SystemCallFilter"])
	}
	if !rs.Whitelist || len(rs.Values) != 1 || rs.Values[0] != "@system-service" {
		t.Fatalf("SystemCallFilter = %+v, want whitelist @system-service", rs)
	}
	af, ok := m["RestrictAddressFamilies"].(restrictSet)
	if !ok || !af.Whitelist {
		t.Fatalf("RestrictAddressFamilies = %+v, want whitelist", af)
	}
}

func TestBuildProperties_LimitsSetOnlyWhenNonZero(t *testing.T) {
	m := propMap(t, validSpec())
	for _, name := range []string{"MemoryMax", "TasksMax", "CPUQuotaPerSecUSec"} {
		if _, ok := m[name]; ok {
			t.Errorf("limit %q should be absent when zero", name)
		}
	}

	spec := validSpec()
	spec.Limits = Limits{MemoryMaxBytes: 512 << 20, CPUQuotaPercent: 50, TasksMax: 64}
	m = propMap(t, spec)
	if m["MemoryMax"].(uint64) != 512<<20 {
		t.Errorf("MemoryMax = %v", m["MemoryMax"])
	}
	if m["TasksMax"].(uint64) != 64 {
		t.Errorf("TasksMax = %v", m["TasksMax"])
	}
	// 50% = 500_000 us/s
	if m["CPUQuotaPerSecUSec"].(uint64) != 500_000 {
		t.Errorf("CPUQuotaPerSecUSec = %v, want 500000", m["CPUQuotaPerSecUSec"])
	}
}

func TestBuildProperties_ExecStartArgvIncludesArgv0(t *testing.T) {
	spec := validSpec()
	spec.Args = []string{"-jar", "app.jar"}
	m := propMap(t, spec)
	items, ok := m["ExecStart"].([]execStartItem)
	if !ok || len(items) != 1 {
		t.Fatalf("ExecStart = %T %v", m["ExecStart"], m["ExecStart"])
	}
	if len(items[0].Argv) != 3 || items[0].Argv[0] != spec.ExecPath || items[0].Argv[1] != "-jar" {
		t.Fatalf("Argv = %v", items[0].Argv)
	}
}

func TestValidateSpec_Rejections(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*UnitSpec)
		want error
	}{
		{"bad unit name (no prefix)", func(s *UnitSpec) { s.Name = "evil.service" }, ErrInvalidUnitName},
		{"bad unit name (slash)", func(s *UnitSpec) { s.Name = "nervus-a/b.service" }, ErrInvalidUnitName},
		{"bad unit name (no .service)", func(s *UnitSpec) { s.Name = "nervus-x" }, ErrInvalidUnitName},
		{"relative exec", func(s *UnitSpec) { s.ExecPath = "bin/app" }, ErrInvalidExec},
		{"exec with newline", func(s *UnitSpec) { s.ExecPath = "/x\n/y" }, ErrInvalidExec},
		{"relative workingdir", func(s *UnitSpec) { s.WorkingDir = "data" }, ErrInvalidWorkingDir},
		{"env without =", func(s *UnitSpec) { s.Env = []string{"NOEQUALS"} }, ErrInvalidEnv},
		{"env bad key", func(s *UnitSpec) { s.Env = []string{"1BAD=x"} }, ErrInvalidEnv},
		{"env newline injection", func(s *UnitSpec) { s.Env = []string{"K=v\nFoo=bar"} }, ErrInvalidEnv},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := validSpec()
			c.mut(&spec)
			if _, err := BuildProperties(spec); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestBuildProperties_BindToUnit(t *testing.T) {
	m := propMap(t, validSpec())
	if _, ok := m["BindsTo"]; ok {
		t.Fatal("BindsTo should be absent when BindToUnit empty")
	}
	spec := validSpec()
	spec.BindToUnit = "nervud.service"
	m = propMap(t, spec)
	bt, ok := m["BindsTo"].([]string)
	if !ok || len(bt) != 1 || bt[0] != "nervud.service" {
		t.Fatalf("BindsTo = %v, want [nervud.service]", m["BindsTo"])
	}
	af, ok := m["After"].([]string)
	if !ok || len(af) != 1 || af[0] != "nervud.service" {
		t.Fatalf("After = %v, want [nervud.service]", m["After"])
	}
}

func TestValidUnitName(t *testing.T) {
	ok := []string{
		"nervus-com.example.app-main.service",
		"nervus-a-b.service",
		"nervus-x.y.z-worker_1.service",
	}
	for _, n := range ok {
		if !validUnitName(n) {
			t.Errorf("validUnitName(%q) = false, want true", n)
		}
	}
	bad := []string{
		"", "systemd.service", "nervus-.service", "nervus-A.service",
		"nervus-a b.service", "nervus-a/b.service", "nervus-a.service\n",
	}
	for _, n := range bad {
		if validUnitName(n) {
			t.Errorf("validUnitName(%q) = true, want false", n)
		}
	}
}

func TestBuildProperties_DeviceAccessDefaultsClosed(t *testing.T) {

	m := propMap(t, validSpec())
	if m["PrivateDevices"] != true {
		t.Errorf("unexpected systemd result; PrivateDevices = %v, want true", m["PrivateDevices"])
	}
	if m["DevicePolicy"] != "closed" {
		t.Errorf("unexpected systemd result; DevicePolicy = %v, want closed", m["DevicePolicy"])
	}
}

func TestBuildProperties_DeviceAccessOptIn(t *testing.T) {
	spec := validSpec()
	spec.Sandbox.AllowDeviceAccess = true
	m := propMap(t, spec)

	if m["PrivateDevices"] != false {
		t.Errorf("PrivateDevices = %v, want false", m["PrivateDevices"])
	}
	if m["DevicePolicy"] != "auto" {
		t.Errorf("DevicePolicy = %v, want auto", m["DevicePolicy"])
	}

	if m["NoNewPrivileges"] != true {
		t.Error("unexpected systemd result; NoNewPrivileges")
	}
	if m["ProtectSystem"] != "strict" {
		t.Error("unexpected systemd result; ProtectSystem")
	}
	if rs, ok := m["SystemCallFilter"].(restrictSet); !ok || !rs.Whitelist {
		t.Error("unexpected systemd result; SystemCallFilter")
	}
}

func TestBuildProperties_CollectModeIsSet(t *testing.T) {

	//

	m := propMap(t, validSpec())
	if got := m["CollectMode"]; got != "inactive-or-failed" {
		t.Fatalf("CollectMode = %v, want inactive-or-failed", got)
	}
}

func TestBuildProperties_CollectModeSurvivesDeviceAccess(t *testing.T) {

	spec := validSpec()
	spec.Sandbox.AllowDeviceAccess = true
	m := propMap(t, spec)
	if got := m["CollectMode"]; got != "inactive-or-failed" {
		t.Fatalf("CollectMode = %v, want inactive-or-failed", got)
	}
}

func TestBuildProperties_BindReadOnlyPathsForX11(t *testing.T) {
	spec := validSpec()
	spec.Sandbox.BindReadOnlyPaths = []string{"/tmp/.X11-unix"}
	m := propMap(t, spec)

	binds, ok := m["BindReadOnlyPaths"].([]bindPath)
	if !ok {
		t.Fatalf("BindReadOnlyPaths type = %T, want []bindPath", m["BindReadOnlyPaths"])
	}
	if len(binds) != 1 {
		t.Fatalf("len(binds) = %d, want 1", len(binds))
	}
	b := binds[0]

	if b.Source != "/tmp/.X11-unix" || b.Destination != "/tmp/.X11-unix" {
		t.Errorf("unexpected systemd result; bind = %s -> %s; expected a different value", b.Source, b.Destination)
	}

	if !b.IgnoreENOENT {
		t.Error("unexpected systemd result; IgnoreENOENT true unit")
	}

	if m["PrivateTmp"] != true {
		t.Error("unexpected systemd result; X11 socket PrivateTmp")
	}
}

func TestBuildProperties_NoBindPathsByDefault(t *testing.T) {

	m := propMap(t, validSpec())
	if _, ok := m["BindReadOnlyPaths"]; ok {
		t.Error("unexpected systemd result; BindReadOnlyPaths")
	}
}
