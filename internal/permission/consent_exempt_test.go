package permission

import "testing"

const storageUser = "perm.storage.user"

// 系统软件的 USER_CONSENT 权限不需要运行期同意.
//
// 在此之前, 一个随镜像发布的文件管理器装好之后永远拿不到 perm.storage.user:
// 运行期状态默认 NOT_REQUESTED, 而全系统能改它的只有管理通道的 nervusctl.
// 表现是界面报"用户目录不可写", 而没有任何地方能解决它
func TestAllowed_SystemSoftwareSkipsRuntimeConsent(t *testing.T) {
	r := NewDefaultRegistry()
	if err := r.Replace([]Grant{{
		PackageID:     "nervus.filemanager",
		Permissions:   []string{storageUser},
		ConsentExempt: true,
	}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	if got := r.GrantStateOf("nervus.filemanager", storageUser); got != GrantStateNotRequested {
		t.Fatalf("运行期状态 = %v, want NOT_REQUESTED（豁免不该伪造一条授予记录）", got)
	}
	if !r.Allowed("nervus.filemanager", storageUser) {
		t.Fatal("系统软件仍被要求运行期同意")
	}
}

// 普通应用照旧必须拿到运行期同意 —— 摄像头, 用户文件, 运动控制这类权限
// 对它们必须逐次询问
func TestAllowed_OrdinaryAppStillNeedsRuntimeConsent(t *testing.T) {
	r := NewDefaultRegistry()
	if err := r.Replace([]Grant{{
		PackageID:   "com.example.app",
		Permissions: []string{storageUser},
		// ConsentExempt 为 false: 不是随镜像发布的系统软件
	}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	if r.Allowed("com.example.app", storageUser) {
		t.Fatal("普通应用未经同意就拿到了 USER_CONSENT 权限")
	}
	if err := r.SetRuntimeState("com.example.app", storageUser, GrantStateGranted); err != nil {
		t.Fatalf("SetRuntimeState: %v", err)
	}
	if !r.Allowed("com.example.app", storageUser) {
		t.Fatal("同意之后仍不放行")
	}
}

// 豁免【不能】越过安装期裁决: 系统软件照样只拿得到 IntersectAt 批准的那些.
//
// 把这两件事混为一谈会让"随镜像发布"变成一张万能通行证 —— 那时 manifest 里
// 多写一条权限就等于拿到它
func TestAllowed_ExemptionDoesNotBypassInstallSet(t *testing.T) {
	r := NewDefaultRegistry()
	if err := r.Replace([]Grant{{
		PackageID: "nervus.filemanager",
		// 安装期一条都没拿到
		Permissions:   nil,
		ConsentExempt: true,
	}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if r.Allowed("nervus.filemanager", storageUser) {
		t.Fatal("豁免越过了安装期集合")
	}
}

// 豁免随 Replace 原子换入. 一个包从系统软件变成普通包 (理论上只会发生在
// 重装成动态安装包时) 之后, 下一次 Allowed 必须立刻看到新判定
func TestAllowed_ExemptionIsReplacedAtomically(t *testing.T) {
	r := NewDefaultRegistry()
	if err := r.Replace([]Grant{{
		PackageID: "com.example.app", Permissions: []string{storageUser}, ConsentExempt: true,
	}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !r.Allowed("com.example.app", storageUser) {
		t.Fatal("豁免未生效")
	}

	if err := r.Replace([]Grant{{
		PackageID: "com.example.app", Permissions: []string{storageUser},
	}}); err != nil {
		t.Fatalf("Replace again: %v", err)
	}
	if r.Allowed("com.example.app", storageUser) {
		t.Fatal("撤掉豁免后仍然放行")
	}
}
