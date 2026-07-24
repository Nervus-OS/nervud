package pkgregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func hashOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestVerifyDigests_Clean(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bin/app", "hello")

	diff, err := VerifyDigests(root, map[string]string{"bin/app": hashOf("hello")})
	if err != nil {
		t.Fatalf("VerifyDigests: %v", err)
	}
	if !diff.Clean() {
		t.Fatalf("want clean diff, got %+v", diff)
	}
}

func TestVerifyDigests_DetectsMismatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bin/app", "tampered")

	diff, err := VerifyDigests(root, map[string]string{"bin/app": hashOf("original")})
	if err != nil {
		t.Fatalf("VerifyDigests: %v", err)
	}
	if len(diff.Mismatched) != 1 || diff.Mismatched[0] != "bin/app" {
		t.Fatalf("want bin/app in Mismatched, got %+v", diff)
	}
	if diff.Clean() {
		t.Fatal("mismatched digest must not be reported clean")
	}
}

func TestVerifyDigests_DetectsMissing(t *testing.T) {
	root := t.TempDir()
	diff, err := VerifyDigests(root, map[string]string{"bin/app": hashOf("x")})
	if err != nil {
		t.Fatalf("VerifyDigests: %v", err)
	}
	if len(diff.Missing) != 1 || diff.Missing[0] != "bin/app" {
		t.Fatalf("want bin/app in Missing, got %+v", diff)
	}
}

func TestVerifyDigests_DetectsExtra(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bin/app", "hello")
	writeFile(t, root, "bin/backdoor", "evil")

	diff, err := VerifyDigests(root, map[string]string{"bin/app": hashOf("hello")})
	if err != nil {
		t.Fatalf("VerifyDigests: %v", err)
	}
	if len(diff.Extra) != 1 || diff.Extra[0] != "bin/backdoor" {
		t.Fatalf("want bin/backdoor in Extra, got %+v", diff)
	}
}
