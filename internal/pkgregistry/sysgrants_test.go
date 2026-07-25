package pkgregistry

import (
	"context"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

// sysEntry 造一个系统镜像来源的 Entry。
func sysEntry(id string, perms []string, trust identity.TrustProfile, roles []string) Entry {
	return Entry{
		Manifest:      Manifest{PackageID: id, Version: "1.0.0", Permissions: perms},
		ActiveVersion: "1.0.0",
		UID:           20000,
		Trust:         trust,
		Source:        SourceSystemImage,
		SignerRoles:   roles,
	}
}

// 系统镜像包必须真的拿到裁决结果。这是本文件存在的理由：没有它，
// GrantedPermissions 恒为 nil，每个系统服务注册 endpoint 都会被拒。
func TestArbitrateSystemGrants_FillsGrantedPermissions(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	entries := []Entry{
		sysEntry("nervus.pkgmanagerd", []string{"perm.service.register"}, identity.TrustPlatform, []string{"platform-release"}),
	}
	mod.arbitrateSystemGrants(context.Background(), entries)

	got := entries[0].GrantedPermissions
	if len(got) != 1 || got[0] != "perm.service.register" {
		t.Fatalf("granted permissions = %v, want [perm.service.register]", got)
	}
}

// trust 与签名角色必须原样喂给 Intersect，否则 RequireSignerRole 类权限
// （perm.safety.rearm）会因为拿不到角色而永远被拒。
func TestArbitrateSystemGrants_PassesTrustAndSignerRoles(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)

	var gotTrust identity.TrustProfile
	var gotRoles []string
	perm.intersect = func(req []string, trust identity.TrustProfile, roles []string) ([]string, []string) {
		gotTrust, gotRoles = trust, roles
		return req, nil
	}

	entries := []Entry{
		sysEntry("nervus.safety.recovery", []string{"perm.safety.rearm"}, identity.TrustPlatform, []string{"platform-release"}),
	}
	mod.arbitrateSystemGrants(context.Background(), entries)

	if gotTrust != identity.TrustPlatform {
		t.Errorf("trust = %v, want %v", gotTrust, identity.TrustPlatform)
	}
	if len(gotRoles) != 1 || gotRoles[0] != "platform-release" {
		t.Errorf("signer roles = %v, want [platform-release]", gotRoles)
	}
}

// 动态安装的 Entry 绝不能被重算：它带着 Install 当时的裁决结果从记账文件
// 读回来。用【当前】的 trust 重算会造成一次静默的权限漂移。
func TestArbitrateSystemGrants_LeavesDynamicInstallsAlone(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)

	called := false
	perm.intersect = func(req []string, _ identity.TrustProfile, _ []string) ([]string, []string) {
		called = true
		return req, nil
	}

	entries := []Entry{{
		Manifest:           Manifest{PackageID: "com.example.app", Permissions: []string{"perm.service.register"}},
		Source:             SourceDynamicInstall,
		GrantedPermissions: []string{"perm.installed.at.install.time"},
	}}
	mod.arbitrateSystemGrants(context.Background(), entries)

	if called {
		t.Error("Intersect was called for a dynamic install; that would silently re-decide an install-time grant")
	}
	if got := entries[0].GrantedPermissions; len(got) != 1 || got[0] != "perm.installed.at.install.time" {
		t.Errorf("granted permissions = %v, want the persisted set untouched", got)
	}
}

// 被拒的权限要留下审计痕迹——否则「服务起来了但用不了」没有任何线索。
func TestArbitrateSystemGrants_AuditsDenied(t *testing.T) {
	mod, _, _, aud, perm := newTestInstallerWithPerm(t)

	perm.intersect = func(_ []string, _ identity.TrustProfile, _ []string) ([]string, []string) {
		return nil, []string{"perm.safety.rearm"}
	}

	entries := []Entry{
		sysEntry("nervus.safety.recovery", []string{"perm.safety.rearm"}, identity.TrustOrdinary, nil),
	}
	mod.arbitrateSystemGrants(context.Background(), entries)

	for _, ev := range aud.events {
		if ev.Action == "pkgregistry.Intersect" && ev.Denied {
			return
		}
	}
	t.Fatalf("want a denied pkgregistry.Intersect audit event, got %+v", aud.events)
}
