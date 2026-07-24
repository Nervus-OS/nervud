package pkgregistry

import (
	"errors"
	"strings"
	"testing"
)

// validManifestJSON 是一份通过全部结构校验的 v1 manifest（应用层架构决策 §3.3）
func validManifestJSON() string {
	return `{
		"schema": 1,
		"package_id": "com.example.app",
		"label": "Example",
		"version": "1.0.0",
		"version_code": 100,
		"min_nervus_api": 1,
		"target_nervus_api": 1,
		"supported_abis": ["linux-x86_64"],
		"digests": {"bin/app": "deadbeef"},
		"permissions": ["net.wifi"],
		"components": [
			{"id": "main", "type": "app", "entry": "bin/app", "runtime": "native", "launch_mode": "on-demand"}
		]
	}`
}

func TestParseManifest_Valid(t *testing.T) {
	m, err := ParseManifest([]byte(validManifestJSON()))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.PackageID != "com.example.app" || m.Version != "1.0.0" || m.VersionCode != 100 {
		t.Fatalf("got %+v", m)
	}
	if len(m.Components) != 1 || m.Components[0].Type != ComponentApp {
		t.Fatalf("components not parsed: %+v", m.Components)
	}
	if m.Components[0].Runtime != RuntimeNative || m.Components[0].LaunchMode != LaunchOnDemand {
		t.Fatalf("component fields not parsed: %+v", m.Components[0])
	}
	// Signer 永远不能从 JSON 里读到——它只能来自独立的签名验证
	if m.Signer != "" {
		t.Fatalf("Signer must never come from JSON, got %q", m.Signer)
	}
}

func TestParseManifest_RejectsUnknownField(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","version_code":1,"min_nervus_api":1,
		"target_nervus_api":1,"supported_abis":["linux-x86_64"],"digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x","runtime":"native","launch_mode":"manual"}],
		"unknown_field":true}`
	if _, err := ParseManifest([]byte(data)); err == nil {
		t.Fatal("未知字段必须被拒绝，而不是静默忽略")
	}
}

func TestParseManifest_RejectsUnsupportedSchema(t *testing.T) {
	data := `{"schema":2,"package_id":"a","version":"1","digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("err = %v, want ErrUnsupportedSchema", err)
	}
}

// min_nervus_api 高于平台时必须在“未知字段”之前给出清晰的 ErrPlatformTooOld
// （应用层架构决策 §9.2 的两段解析）
func TestParseManifest_PlatformTooOld(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","min_nervus_api":999,
		"digests":{"x":"y"},"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrPlatformTooOld) {
		t.Fatalf("err = %v, want ErrPlatformTooOld", err)
	}
}

func TestParseManifest_RejectsEmptyPackageID(t *testing.T) {
	data := `{"schema":1,"package_id":"","version":"1","digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrEmptyPackageID) {
		t.Fatalf("err = %v, want ErrEmptyPackageID", err)
	}
}

// 恶意 package_id 必须在解析入口就被拒（应用层架构决策 §9.1）——它会被拼进
// 记账文件名，非法字符等于路径写逃逸
func TestParseManifest_RejectsInvalidPackageID(t *testing.T) {
	cases := []string{"../../../tmp/evil", "Com.Example", "a/b", "a..b", "a.", ".a", "1abc", strings.Repeat("a", 129)}
	for _, id := range cases {
		data := `{"schema":1,"package_id":"` + id + `","version":"1","version_code":1,` +
			`"min_nervus_api":1,"target_nervus_api":1,"supported_abis":["linux-x86_64"],` +
			`"digests":{"x":"y"},"components":[{"id":"m","type":"app","entry":"x","runtime":"native","launch_mode":"manual"}]}`
		if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrInvalidPackageID) {
			t.Errorf("package_id=%q: err = %v, want ErrInvalidPackageID", id, err)
		}
	}
}

func TestParseManifest_RejectsEmptyVersion(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"","digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrEmptyVersion) {
		t.Fatalf("err = %v, want ErrEmptyVersion", err)
	}
}

func TestParseManifest_RejectsMissingVersionCode(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","min_nervus_api":1,"target_nervus_api":1,
		"supported_abis":["linux-x86_64"],"digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x","runtime":"native","launch_mode":"manual"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrMissingVersionCode) {
		t.Fatalf("err = %v, want ErrMissingVersionCode", err)
	}
}

// supported_abis 必须是 canonical NSOS token；Android NDK 名（arm64-v8a）直接拒绝
func TestParseManifest_RejectsInvalidABI(t *testing.T) {
	for _, abi := range []string{"arm64-v8a", "aarch64", "amd64", ""} {
		data := `{"schema":1,"package_id":"a","version":"1","version_code":1,"min_nervus_api":1,
			"target_nervus_api":1,"supported_abis":["` + abi + `"],"digests":{"x":"y"},
			"components":[{"id":"m","type":"app","entry":"x","runtime":"native","launch_mode":"manual"}]}`
		if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrInvalidABI) {
			t.Errorf("abi=%q: err = %v, want ErrInvalidABI", abi, err)
		}
	}
}

func TestParseManifest_RejectsNoComponents(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","digests":{"x":"y"},"components":[]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrNoComponents) {
		t.Fatalf("err = %v, want ErrNoComponents", err)
	}
}

func TestParseManifest_RejectsNoDigests(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","digests":{},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrNoDigests) {
		t.Fatalf("err = %v, want ErrNoDigests", err)
	}
}

func TestParseManifest_RejectsDuplicateComponentID(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","digests":{"x":"y"},
		"components":[
			{"id":"m","type":"app","entry":"x"},
			{"id":"m","type":"service","entry":"y"}
		]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrDuplicateComponentID) {
		t.Fatalf("err = %v, want ErrDuplicateComponentID", err)
	}
}

func TestParseManifest_RejectsInvalidComponentType(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","digests":{"x":"y"},
		"components":[{"id":"m","type":"daemon","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrInvalidComponentType) {
		t.Fatalf("err = %v, want ErrInvalidComponentType", err)
	}
}

func TestParseManifest_RejectsInvalidRuntime(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","version_code":1,"min_nervus_api":1,
		"target_nervus_api":1,"supported_abis":["linux-x86_64"],"digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x","runtime":"python","launch_mode":"manual"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("err = %v, want ErrInvalidRuntime", err)
	}
}

// app 不能声明 always-on，service 不能声明 manual（应用层架构决策 §3.4）
func TestParseManifest_RejectsLaunchModeTypeMismatch(t *testing.T) {
	appAlwaysOn := `{"schema":1,"package_id":"a","version":"1","version_code":1,"min_nervus_api":1,
		"target_nervus_api":1,"supported_abis":["linux-x86_64"],"digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x","runtime":"jvm","launch_mode":"always-on"}]}`
	if _, err := ParseManifest([]byte(appAlwaysOn)); !errors.Is(err, ErrLaunchModeTypeMismatch) {
		t.Fatalf("app always-on: err = %v, want ErrLaunchModeTypeMismatch", err)
	}
	svcManual := `{"schema":1,"package_id":"a","version":"1","version_code":1,"min_nervus_api":1,
		"target_nervus_api":1,"supported_abis":["linux-x86_64"],"digests":{"x":"y"},
		"components":[{"id":"m","type":"service","entry":"x","runtime":"jvm","launch_mode":"manual"}]}`
	if _, err := ParseManifest([]byte(svcManual)); !errors.Is(err, ErrLaunchModeTypeMismatch) {
		t.Fatalf("service manual: err = %v, want ErrLaunchModeTypeMismatch", err)
	}
}

// 入口文件必须被 digests 覆盖，否则等于允许运行一个未经完整性复核的可执行文件
func TestParseManifest_RejectsEntryNotInDigests(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","version_code":1,"min_nervus_api":1,
		"target_nervus_api":1,"supported_abis":["linux-x86_64"],"digests":{"other":"y"},
		"components":[{"id":"m","type":"app","entry":"x","runtime":"native","launch_mode":"manual"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrEntryNotInDigests) {
		t.Fatalf("err = %v, want ErrEntryNotInDigests", err)
	}
}

// 入口路径解析后必须仍位于 Package 目录内（架构 §8）——路径穿越必须拒绝
func TestParseManifest_RejectsEntryPathEscape(t *testing.T) {
	cases := []string{"../../etc/passwd", "/etc/passwd", "..", "a/../../b"}
	for _, entry := range cases {
		data := `{"schema":1,"package_id":"a","version":"1","digests":{"x":"y"},
			"components":[{"id":"m","type":"app","entry":"` + entry + `"}]}`
		if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrUnsafeRelPath) {
			t.Errorf("entry=%q: err = %v, want ErrUnsafeRelPath", entry, err)
		}
	}
}

// digest 清单的键同样是包内相对路径，必须满足同一条安全规则
func TestParseManifest_RejectsDigestPathEscape(t *testing.T) {
	data := `{"schema":1,"package_id":"a","version":"1","digests":{"../../etc/passwd":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrUnsafeRelPath) {
		t.Fatalf("err = %v, want ErrUnsafeRelPath", err)
	}
}

func TestValidPackageID(t *testing.T) {
	cases := []struct {
		id string
		ok bool
	}{
		{"com.example.app", true},
		{"nervus.pkgmanagerd", true},
		{"a", true},
		{"a_b.c9", true},
		{"", false},
		{"Com.Example", false},       // 大写
		{"../../../tmp/evil", false}, // 路径逃逸
		{"a/b", false},               // 斜杠
		{"a..b", false},              // 空段
		{"a.", false},                // 尾空段
		{".a", false},                // 首空段
		{"1abc", false},              // 数字首字符
		{"_x", false},                // 下划线首字符
		{strings.Repeat("a", 129), false},
	}
	for _, c := range cases {
		if got := validPackageID(c.id); got != c.ok {
			t.Errorf("validPackageID(%q) = %v, want %v", c.id, got, c.ok)
		}
	}
}

func TestValidRelPath(t *testing.T) {
	cases := []struct {
		p  string
		ok bool
	}{
		{"bin/app", true},
		{"app", true},
		{"", false},
		{"/etc/passwd", false},
		{"..", false},
		{"../x", false},
		{"a/../../b", false},
		{"a/../b", true}, // Clean 后仍在内
		{".", false},
	}
	for _, c := range cases {
		if got := validRelPath(c.p); got != c.ok {
			t.Errorf("validRelPath(%q) = %v, want %v", c.p, got, c.ok)
		}
	}
}
