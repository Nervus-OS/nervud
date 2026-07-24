package permission

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

// grant 把一个包的安装期权限集合投影进 Registry
func grant(t *testing.T, r *Registry, pkg string, perms ...string) {
	t.Helper()
	if err := r.Replace([]Grant{{PackageID: pkg, Permissions: perms}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
}

func TestAllowed_GrantInstallNoRuntimeNeeded(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	grant(t, r, "com.a", "perm.diagnostics.read")
	// GrantInstall 权限：安装期集合里有就放行，不需要运行期状态
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("GrantInstall perm should be allowed once in install-set")
	}
}

func TestAllowed_GrantUserRequiresRuntimeGrant(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	// 安装期授予「可请求」camera
	grant(t, r, "com.a", "perm.camera.capture")

	// 运行期未授予 → 不放行（危险权限双重门）
	if r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("GrantUser perm must NOT be allowed before runtime grant")
	}
	// 用户确认授予 → 放行
	if err := r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted); err != nil {
		t.Fatalf("SetRuntimeState: %v", err)
	}
	if !r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("GrantUser perm should be allowed after runtime grant")
	}
	// 撤销 → 立即不放行（我们独有的立即撤销，§6.4）
	if err := r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateDenied); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("revoked GrantUser perm must be denied immediately")
	}
}

func TestAllowed_NotInInstallSetAlwaysDenied(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	// 即便运行期状态硬设为 Granted，安装期没有就绝不放行
	if err := r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted); err != nil {
		t.Fatalf("SetRuntimeState: %v", err)
	}
	if r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("perm not in install-set must be denied even if runtime-granted")
	}
}

func TestSetRuntimeState_RejectsNonUserPerm(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	// perm.diagnostics.read 是 GrantInstall，不该有运行期状态
	if err := r.SetRuntimeState("com.a", "perm.diagnostics.read", GrantStateGranted); err == nil {
		t.Fatal("SetRuntimeState on a non-GrantUser perm should error")
	}
	// 未知权限
	if err := r.SetRuntimeState("com.a", "perm.nope", GrantStateGranted); err == nil {
		t.Fatal("SetRuntimeState on unknown perm should error")
	}
}

// fakeRevoker 记录被撤租的包
type fakeRevoker struct{ revoked []string }

func (f *fakeRevoker) RevokeByPackage(pkg string) error {
	f.revoked = append(f.revoked, pkg)
	return nil
}

func TestRevokeMotionPerm_TriggersLeaseRevoker(t *testing.T) {
	dir := t.TempDir()
	r := NewRegistry(DefaultCatalog())
	rev := &fakeRevoker{}
	r.SetGrantStore(dir, rev, nil)
	grant(t, r, "com.a", "perm.motion.control")

	// 授予 motion → 撤销 motion：必须联动撤租（§6.4）
	if err := r.SetRuntimeState("com.a", "perm.motion.control", GrantStateGranted); err != nil {
		t.Fatalf("grant motion: %v", err)
	}
	if len(rev.revoked) != 0 {
		t.Fatalf("granting must not revoke: %+v", rev.revoked)
	}
	if err := r.SetRuntimeState("com.a", "perm.motion.control", GrantStateDenied); err != nil {
		t.Fatalf("revoke motion: %v", err)
	}
	if len(rev.revoked) != 1 || rev.revoked[0] != "com.a" {
		t.Fatalf("revoking motion perm must call RevokeByPackage: %+v", rev.revoked)
	}

	// 非 motion 组权限撤销不应触发撤租
	grant(t, r, "com.a", "perm.motion.control", "perm.camera.capture")
	_ = r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted)
	_ = r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateDenied)
	if len(rev.revoked) != 1 {
		t.Fatalf("revoking non-motion perm must NOT revoke leases: %+v", rev.revoked)
	}
}

func TestGrantState_Persistence(t *testing.T) {
	dir := t.TempDir()

	r1 := NewRegistry(DefaultCatalog())
	r1.SetGrantStore(dir, nil, nil)
	if err := r1.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted); err != nil {
		t.Fatalf("set: %v", err)
	}
	// 文件应存在
	if _, err := os.Stat(filepath.Join(dir, grantStateFile)); err != nil {
		t.Fatalf("grant state file not written: %v", err)
	}

	// 新 Registry 从同目录载入，状态应恢复
	r2 := NewRegistry(DefaultCatalog())
	r2.SetGrantStore(dir, nil, nil)
	if r2.GrantStateOf("com.a", "perm.camera.capture") != GrantStateGranted {
		t.Fatal("grant state not restored from disk")
	}
	grant(t, r2, "com.a", "perm.camera.capture")
	if !r2.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("restored grant should make Allowed true")
	}
}

func TestIntersect_RequireSignerRole(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	// perm.authority.reboot 需 platform-release 角色 + Platform trust
	// 有 Platform trust 但角色是 platform-systemapp（如 Launcher）→ 拒
	g, d := r.Intersect([]string{"perm.authority.reboot"}, identity.TrustPlatform, []string{"platform-systemapp"})
	if len(g) != 0 || len(d) != 1 {
		t.Fatalf("reboot without platform-release role must be denied: g=%v d=%v", g, d)
	}
	// platform-release 角色 → 授予
	g, d = r.Intersect([]string{"perm.authority.reboot"}, identity.TrustPlatform, []string{"platform-release"})
	if len(g) != 1 || len(d) != 0 {
		t.Fatalf("reboot with platform-release role should be granted: g=%v d=%v", g, d)
	}
}

func TestIntersect_RegisterSplit(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	// register.private 是 Ordinary → 用户应用可拿
	g, _ := r.Intersect([]string{"perm.service.register.private"}, identity.TrustOrdinary, []string{"developer"})
	if len(g) != 1 {
		t.Fatalf("register.private should be grantable to Ordinary: %v", g)
	}
	// 跨包 register 需 OEM → Ordinary 拿不到
	_, d := r.Intersect([]string{"perm.service.register"}, identity.TrustOrdinary, []string{"developer"})
	if len(d) != 1 {
		t.Fatalf("cross-package register must require OEM+: denied=%v", d)
	}
}
