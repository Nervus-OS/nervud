package systemd

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestCapBits_MatchKernelValues(t *testing.T) {

	want := map[string]uint{
		"CAP_CHOWN":              0,
		"CAP_SETUID":             7,
		"CAP_NET_ADMIN":          12,
		"CAP_NET_RAW":            13,
		"CAP_SYS_ADMIN":          21,
		"CAP_MKNOD":              27,
		"CAP_SETFCAP":            31,
		"CAP_CHECKPOINT_RESTORE": 40,
	}
	for name, bit := range want {
		if got, ok := capBits[name]; !ok {
			t.Errorf("unexpected systemd result; capBits %s", name)
		} else if got != bit {
			t.Errorf("capBits[%s] = %d, want %d", name, got, bit)
		}
	}
}

func TestCapMask_Builds(t *testing.T) {
	got, err := capMask([]string{"CAP_NET_ADMIN", "CAP_NET_RAW"})
	if err != nil {
		t.Fatalf("capMask: %v", err)
	}
	want := uint64(1<<12 | 1<<13)
	if got != want {
		t.Fatalf("capMask = %#x, want %#x", got, want)
	}
}

//

func TestCapMask_RejectsUnknown(t *testing.T) {
	_, err := capMask([]string{"CAP_NET_ADMIN", "CAP_NET_ADMN"})
	if !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("err = %v, want ErrUnknownCapability", err)
	}
}

//

func TestBuildProperties_CapabilitiesAreUint64(t *testing.T) {
	props, err := BuildProperties(UnitSpec{
		Name:       "nervus-test.pkg-main.service",
		ExecPath:   "/usr/bin/true",
		WorkingDir: "/var/lib/nervus/package-data/test.pkg",
		Sandbox:    Sandbox{AmbientCapabilities: []string{"CAP_NET_ADMIN"}},
	})
	if err != nil {
		t.Fatalf("BuildProperties: %v", err)
	}

	seen := 0
	for _, p := range props {
		if p.Name != "AmbientCapabilities" && p.Name != "CapabilityBoundingSet" {
			continue
		}
		seen++
		if sig := p.Value.Signature().String(); sig != "t" {
			t.Errorf("unexpected systemd result; value = %s %q, want \"t\" uint64 systemd"+
				"systemd test value 2ae2e2; Unexpected message contents StartTransientUnit", p.Name, sig)
		}
		if v, ok := p.Value.Value().(uint64); !ok || v != 1<<12 {
			t.Errorf("%s = %#v, want uint64(1<<12)", p.Name, p.Value.Value())
		}
	}
	if seen != 2 {
		t.Errorf("unexpected systemd result; value = %d capability, want 2 ambient + bounding", seen)
	}
}

func TestBuildProperties_NoCapabilitiesNoProperty(t *testing.T) {
	props, err := BuildProperties(UnitSpec{
		Name:       "nervus-test.pkg-main.service",
		ExecPath:   "/usr/bin/true",
		WorkingDir: "/var/lib/nervus/package-data/test.pkg",
	})
	if err != nil {
		t.Fatalf("BuildProperties: %v", err)
	}
	for _, p := range props {
		if p.Name == "AmbientCapabilities" || p.Name == "CapabilityBoundingSet" {
			t.Errorf("unexpected systemd result; capability %s", p.Name)
		}
	}
}

func TestBuildProperties_AddressFamiliesAppendToBaseline(t *testing.T) {
	props, err := BuildProperties(UnitSpec{
		Name:       "nervus-test.pkg-main.service",
		ExecPath:   "/usr/bin/true",
		WorkingDir: "/var/lib/nervus/package-data/test.pkg",
		Sandbox:    Sandbox{ExtraAddressFamilies: []string{"AF_BLUETOOTH"}},
	})
	if err != nil {
		t.Fatalf("BuildProperties: %v", err)
	}
	var got []string
	for _, p := range props {
		if p.Name != "RestrictAddressFamilies" {
			continue
		}
		rs, ok := p.Value.Value().(restrictSet)
		if !ok {
			t.Fatalf("unexpected systemd result; RestrictAddressFamilies %T, want restrictSet", p.Value.Value())
		}
		if !rs.Whitelist {
			t.Error("unexpected systemd result; RestrictAddressFamilies")
		}
		got = rs.Values
	}
	want := []string{"AF_UNIX", "AF_INET", "AF_INET6", "AF_BLUETOOTH"}
	if len(got) != len(want) {
		t.Fatalf("unexpected systemd result; value = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected systemd result; value = %v, want %v", got, want)
		}
	}
}

var _ = dbus.MakeVariant
