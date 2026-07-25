package systemd

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

// capBits 是对 capabilities(7) 的抄写，抄错一个数字的后果是给错能力——
// 而错给的那条不会有任何症状，只有想用的那条 EPERM。逐条钉住已知取值。
func TestCapBits_MatchKernelValues(t *testing.T) {
	// 取值来自 linux/capability.h。挑的是边界与最容易记混的几条：
	// 首、尾、蓝牙要用的两条、以及 MKNOD（它排在 27 而不是按名字顺序）。
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
			t.Errorf("capBits 缺 %s", name)
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

// 不认识的名字必须【整体失败】。
//
// 跳过它的话组件照常起来、照常缺那个能力，症状是运行期 EPERM，而日志里
// 没有任何线索说少了一条。
func TestCapMask_RejectsUnknown(t *testing.T) {
	_, err := capMask([]string{"CAP_NET_ADMIN", "CAP_NET_ADMN"})
	if !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("err = %v, want ErrUnknownCapability", err)
	}
}

// AmbientCapabilities / CapabilityBoundingSet 的 D-Bus 签名必须是 t（uint64）。
//
// 【这条曾经踩过】：发字符串数组时 systemd 以
// "Failed to set unit properties: Unexpected message contents" 整体拒绝，
// 错误里不提是哪个属性，unit 一个都起不来。unit 文件里能写
// "AmbientCapabilities=CAP_NET_ADMIN" 是配置语法糖，与 D-Bus API 无关。
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
			t.Errorf("%s 的签名是 %q, want \"t\"（uint64）—— systemd 会以 "+
				"Unexpected message contents 拒绝整个 StartTransientUnit", p.Name, sig)
		}
		if v, ok := p.Value.Value().(uint64); !ok || v != 1<<12 {
			t.Errorf("%s = %#v, want uint64(1<<12)", p.Name, p.Value.Value())
		}
	}
	if seen != 2 {
		t.Errorf("找到 %d 条 capability 属性, want 2（ambient + bounding）", seen)
	}
}

// 不声明 capability 时不该下发这两个属性——下发一个 0 掩码会让
// systemctl show 的输出与「什么都没配」区分不开。
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
			t.Errorf("没声明 capability 却下发了 %s", p.Name)
		}
	}
}

// 额外地址族要追加在基线之后，且基线不能被覆盖掉。
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
			t.Fatalf("RestrictAddressFamilies 类型是 %T, want restrictSet", p.Value.Value())
		}
		if !rs.Whitelist {
			t.Error("RestrictAddressFamilies 不是白名单模式")
		}
		got = rs.Values
	}
	want := []string{"AF_UNIX", "AF_INET", "AF_INET6", "AF_BLUETOOTH"}
	if len(got) != len(want) {
		t.Fatalf("地址族 = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("地址族 = %v, want %v", got, want)
		}
	}
}

var _ = dbus.MakeVariant
