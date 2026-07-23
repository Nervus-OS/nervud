package pkgregistry

import (
	"errors"
	"testing"
)

func validManifestJSON() string {
	return `{
		"package_id": "com.example.app",
		"version": "1.0.0",
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
	if m.PackageID != "com.example.app" || m.Version != "1.0.0" {
		t.Fatalf("got %+v", m)
	}
	if len(m.Components) != 1 || m.Components[0].Type != ComponentApp {
		t.Fatalf("components not parsed: %+v", m.Components)
	}
	// Signer 永远不能从 JSON 里读到——它只能来自独立的签名验证
	if m.Signer != "" {
		t.Fatalf("Signer must never come from JSON, got %q", m.Signer)
	}
}

func TestParseManifest_RejectsUnknownField(t *testing.T) {
	data := `{"package_id":"a","version":"1","digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}],"unknown_field":true}`
	if _, err := ParseManifest([]byte(data)); err == nil {
		t.Fatal("未知字段必须被拒绝，而不是静默忽略")
	}
}

func TestParseManifest_RejectsEmptyPackageID(t *testing.T) {
	data := `{"package_id":"","version":"1","digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	_, err := ParseManifest([]byte(data))
	if !errors.Is(err, ErrEmptyPackageID) {
		t.Fatalf("err = %v, want ErrEmptyPackageID", err)
	}
}

func TestParseManifest_RejectsEmptyVersion(t *testing.T) {
	data := `{"package_id":"a","version":"","digests":{"x":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	_, err := ParseManifest([]byte(data))
	if !errors.Is(err, ErrEmptyVersion) {
		t.Fatalf("err = %v, want ErrEmptyVersion", err)
	}
}

func TestParseManifest_RejectsNoComponents(t *testing.T) {
	data := `{"package_id":"a","version":"1","digests":{"x":"y"},"components":[]}`
	_, err := ParseManifest([]byte(data))
	if !errors.Is(err, ErrNoComponents) {
		t.Fatalf("err = %v, want ErrNoComponents", err)
	}
}

func TestParseManifest_RejectsNoDigests(t *testing.T) {
	data := `{"package_id":"a","version":"1","digests":{},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	_, err := ParseManifest([]byte(data))
	if !errors.Is(err, ErrNoDigests) {
		t.Fatalf("err = %v, want ErrNoDigests", err)
	}
}

func TestParseManifest_RejectsDuplicateComponentID(t *testing.T) {
	data := `{"package_id":"a","version":"1","digests":{"x":"y"},
		"components":[
			{"id":"m","type":"app","entry":"x"},
			{"id":"m","type":"service","entry":"y"}
		]}`
	_, err := ParseManifest([]byte(data))
	if !errors.Is(err, ErrDuplicateComponentID) {
		t.Fatalf("err = %v, want ErrDuplicateComponentID", err)
	}
}

func TestParseManifest_RejectsInvalidComponentType(t *testing.T) {
	data := `{"package_id":"a","version":"1","digests":{"x":"y"},
		"components":[{"id":"m","type":"daemon","entry":"x"}]}`
	_, err := ParseManifest([]byte(data))
	if !errors.Is(err, ErrInvalidComponentType) {
		t.Fatalf("err = %v, want ErrInvalidComponentType", err)
	}
}

// 入口路径解析后必须仍位于 Package 目录内（架构 §8）——路径穿越必须拒绝
func TestParseManifest_RejectsEntryPathEscape(t *testing.T) {
	cases := []string{"../../etc/passwd", "/etc/passwd", "..", "a/../../b"}
	for _, entry := range cases {
		data := `{"package_id":"a","version":"1","digests":{"x":"y"},
			"components":[{"id":"m","type":"app","entry":"` + entry + `"}]}`
		if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrUnsafeRelPath) {
			t.Errorf("entry=%q: err = %v, want ErrUnsafeRelPath", entry, err)
		}
	}
}

// digest 清单的键同样是包内相对路径，必须满足同一条安全规则——否则
// 完整性复核会去比对包目录之外的文件
func TestParseManifest_RejectsDigestPathEscape(t *testing.T) {
	data := `{"package_id":"a","version":"1","digests":{"../../etc/passwd":"y"},
		"components":[{"id":"m","type":"app","entry":"x"}]}`
	if _, err := ParseManifest([]byte(data)); !errors.Is(err, ErrUnsafeRelPath) {
		t.Fatalf("err = %v, want ErrUnsafeRelPath", err)
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
