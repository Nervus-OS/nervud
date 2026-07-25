package service

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// jvmAppFixture 造一个最小的 jvm + app 组件，用于 buildStartReq 的形状测试。
// 不启动任何进程，只走参数组装那条纯函数路径。
func jvmAppFixture(t *testing.T) (*Manager, pkgregistry.Entry, pkgregistry.Component) {
	t.Helper()
	m := &Manager{inv: authority.DefaultInvariants()}
	e := pkgregistry.Entry{
		Manifest: pkgregistry.Manifest{
			PackageID: "com.example.app",
			Components: []pkgregistry.Component{{
				ID: "main", Type: pkgregistry.ComponentApp,
				Runtime: pkgregistry.RuntimeJVM, Entry: "lib/main.jar",
				LaunchMode: pkgregistry.LaunchManual,
			}},
		},
		ActiveVersion: "1.0.0",
		UID:           20001,
		Source:        pkgregistry.SourceDynamicInstall,
	}
	return m, e, e.Manifest.Components[0]
}

func TestCodeDir_DiffersBySource(t *testing.T) {
	// 两类包的代码布局不同，不能共用一个拼法：
	//   动态安装  <PackageRoot>/<pkg>/<version>/   多版本可共存
	//   系统镜像  <SystemPackageRoot>/<pkg>/       无版本子目录，跟随整镜像 OTA
	//
	// 无条件用 PackageRoot 会让系统包的 ExecStart 指向一个不存在的路径，
	// systemd 在 step EXEC 失败（203/EXEC）——而错误信息只说「找不到可执行
	// 文件」，看不出是布局假设错了。这是端到端验证真撞到的。
	inv := authority.DefaultInvariants()

	sys := pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: "nervus.pkgmanagerd"},
		ActiveVersion: "0.1.0",
		Source:        pkgregistry.SourceSystemImage,
	}
	got := codeDir(inv, sys)
	want := "/usr/lib/nervus/system-packages/nervus.pkgmanagerd"
	if got != want {
		t.Errorf("系统镜像包 codeDir = %q, want %q（无版本子目录）", got, want)
	}

	dyn := pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: "com.example.app"},
		ActiveVersion: "1.2.3",
		Source:        pkgregistry.SourceDynamicInstall,
	}
	got = codeDir(inv, dyn)
	want = "/var/lib/nervus/packages/com.example.app/1.2.3"
	if got != want {
		t.Errorf("动态安装包 codeDir = %q, want %q（带版本子目录）", got, want)
	}
}

func TestCodeDir_SystemPathPassesInvariantCheck(t *testing.T) {
	// 路径包含校验必须认系统镜像根，否则系统包的可执行文件会被判成
	// 「逃出 PackageRoot」而在 Validate 阶段就被拒。
	inv := authority.DefaultInvariants()
	sys := pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: "nervus.pkgmanagerd"},
		ActiveVersion: "0.1.0",
		Source:        pkgregistry.SourceSystemImage,
	}
	exec := filepath.Join(codeDir(inv, sys), "bin/pkgmanagerd")
	if err := inv.CheckContainedInCodeRoot(exec); err != nil {
		t.Fatalf("系统包可执行路径应通过代码根校验: %v", err)
	}
	// 而真正逃逸的仍要被拒
	if err := inv.CheckContainedInCodeRoot("/etc/shadow"); err == nil {
		t.Error("/etc/shadow 必须被拒")
	}
}

// JVM 组件必须拿到可写且可执行的临时目录。
//
// 这条挡的是一个很难查的失败：skiko 等库把 .so 打在 jar 里，运行时解压再
// dlopen。默认落 /tmp，而 PrivateTmp 继承宿主 /tmp 的挂载选项——宿主若是
// noexec，.so 写得进去、dlopen 失败，报 UnsatisfiedLinkError，看不出和沙箱有关。
func TestBuildStartReq_JVMGetsWritableTmpAndHome(t *testing.T) {
	m, e, c := jvmAppFixture(t)
	req, err := m.buildStartReq(e, c, "nervus-com.example.app-main.service")
	if err != nil {
		t.Fatalf("buildStartReq: %v", err)
	}

	dataDir := filepath.Join(m.inv.DataRoot, e.Manifest.PackageID)
	wantTmp := "-Djava.io.tmpdir=" + dataDir
	wantHome := "-Duser.home=" + dataDir

	if !slices.Contains(req.Args, wantTmp) {
		t.Errorf("缺 %q；args=%v", wantTmp, req.Args)
	}
	if !slices.Contains(req.Args, wantHome) {
		t.Errorf("缺 %q；args=%v", wantHome, req.Args)
	}
	// 指到的目录必须真的在可写列表里，否则设了也白设
	if !slices.Contains(req.ReadWritePaths, dataDir) {
		t.Errorf("java.io.tmpdir 指向的 %q 不在 ReadWritePaths=%v 里", dataDir, req.ReadWritePaths)
	}
	// -jar 必须在这些 -D 之后：JVM 把 -jar 之后的都当成程序参数
	tmpIdx := slices.Index(req.Args, wantTmp)
	jarIdx := slices.Index(req.Args, "-jar")
	if jarIdx >= 0 && tmpIdx > jarIdx {
		t.Errorf("-D 参数必须在 -jar 之前，否则会被当成程序参数；args=%v", req.Args)
	}
}
