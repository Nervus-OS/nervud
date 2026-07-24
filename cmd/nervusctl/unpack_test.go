package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type archiveEntry struct {
	name     string
	body     string
	typeflag byte
	mode     int64
}

func buildNspkg(t *testing.T, entries []archiveEntry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pkg.nspkg")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = f.Close() }()

	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Typeflag: tf, Mode: mode, Size: int64(len(e.body))}
		if tf == tar.TypeSymlink {
			hdr.Linkname = e.body
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zstd: %v", err)
	}
	return p
}

func TestUnpackNspkgHappyPath(t *testing.T) {
	nspkg := buildNspkg(t, []archiveEntry{
		{name: "manifest.json", body: `{"schema":1}`},
		{name: "manifest.sig", body: `{}`},
		{name: "bin/app", body: "#!/bin/true", mode: 0o755},
	})
	dest := t.TempDir()
	if err := unpackNspkg(nspkg, dest); err != nil {
		t.Fatalf("unpackNspkg: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	if err != nil || string(got) != `{"schema":1}` {
		t.Fatalf("manifest.json = %q, err %v", got, err)
	}
	bin, err := os.ReadFile(filepath.Join(dest, "bin", "app"))
	if err != nil || string(bin) != "#!/bin/true" {
		t.Fatalf("bin/app = %q, err %v", bin, err)
	}
	fi, _ := os.Stat(filepath.Join(dest, "bin", "app"))
	if fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("exec bit lost: %v", fi.Mode())
	}
}

func TestUnpackRejectsTarSlip(t *testing.T) {
	cases := map[string][]archiveEntry{
		"parent traversal": {{name: "../evil", body: "x"}},
		"absolute path":    {{name: "/etc/evil", body: "x"}},
		"deep traversal":   {{name: "a/../../evil", body: "x"}},
		"symlink":          {{name: "link", body: "/etc/passwd", typeflag: tar.TypeSymlink}},
		"hardlink":         {{name: "hl", body: "manifest.json", typeflag: tar.TypeLink}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			nspkg := buildNspkg(t, entries)
			dest := t.TempDir()
			err := unpackNspkg(nspkg, dest)
			if err == nil {
				t.Fatalf("want error for %s", name)
			}
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "evil")); statErr == nil {
				t.Fatalf("%s: file escaped destination", name)
			}
		})
	}
}

func TestUnpackRejectsEmptyName(t *testing.T) {
	nspkg := buildNspkg(t, []archiveEntry{{name: "", body: "x"}})
	if err := unpackNspkg(nspkg, t.TempDir()); err == nil {
		t.Fatal("want error for empty entry name")
	}
}

func TestUnpackNestedDirs(t *testing.T) {
	nspkg := buildNspkg(t, []archiveEntry{
		{name: "lib/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "lib/sub/file", body: "data"},
	})
	dest := t.TempDir()
	if err := unpackNspkg(nspkg, dest); err != nil {
		t.Fatalf("unpackNspkg: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "lib", "sub", "file")); err != nil || string(got) != "data" {
		t.Fatalf("nested file = %q, err %v", got, err)
	}
}

func TestSafeJoin(t *testing.T) {
	base := filepath.Clean(t.TempDir())
	if _, err := safeJoin(base, "a/b/c"); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	for _, bad := range []string{"", "/abs", "../x", "a/../../x"} {
		if _, err := safeJoin(base, bad); err == nil {
			t.Fatalf("safeJoin accepted bad name %q", bad)
		}
	}
	if _, err := safeJoin(base, strings.Repeat("a", 3)); err != nil {
		t.Fatalf("normal name rejected: %v", err)
	}
}
