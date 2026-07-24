package systemd

import (
	"errors"
	"testing"
)

// propMap 把 BuildProperties 的结果收成 name->value 便于断言
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

	// 沙箱硬项无条件存在
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
	// 零值：不设 limit 属性
	m := propMap(t, validSpec())
	for _, name := range []string{"MemoryMax", "TasksMax", "CPUQuotaPerSecUSec"} {
		if _, ok := m[name]; ok {
			t.Errorf("limit %q should be absent when zero", name)
		}
	}

	// 非零值：设，且 CPU 百分比正确换算成 usec
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
	// argv[0] 必须是 ExecPath 本身，其后接 Args
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
		"", "systemd.service", "nervus-.service", "nervus-A.service", // 大写
		"nervus-a b.service", "nervus-a/b.service", "nervus-a.service\n",
	}
	for _, n := range bad {
		if validUnitName(n) {
			t.Errorf("validUnitName(%q) = true, want false", n)
		}
	}
}
