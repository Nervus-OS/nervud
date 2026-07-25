package service

import (
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

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
