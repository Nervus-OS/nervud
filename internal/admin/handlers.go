// pkgregistry / permission 的对应操作，并把结果投影回 adminwire.Response。
//
// 安全纪律：本文件不做任何安全裁决。签名验证、Arbitrate、OEM 副署、ABI、
// 权限 Intersect、失败补偿全在 pkgregistry.Install/Uninstall 内部。这里只做
//  1. 参数存在性与路径逃逸校验（staging 目录必须是 nervud 掌控的 staging 根的
//     直接子目录）；
//  2. 转调；
//  3. 结果/错误投影。
package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/nervus-os/nervud/internal/adminwire"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// dispatch 按 Request.Cmd 路由。未知命令回 CodeBadRequest（fail-closed，不静默）。
func (s *Server) dispatch(ctx context.Context, req adminwire.Request) adminwire.Response {
	switch req.Cmd {
	case adminwire.CmdBeginStaging:
		return s.handleBeginStaging()
	case adminwire.CmdInstall:
		return s.handleInstall(ctx, req)
	case adminwire.CmdUninstall:
		return s.handleUninstall(ctx, req)
	case adminwire.CmdList:
		return s.handleList()
	case adminwire.CmdSetEnabled:
		return s.handleSetEnabled(ctx, req)
	case adminwire.CmdSetPermission:
		return s.handleSetPermission(req)
	default:
		return badRequest("unknown command %q", req.Cmd)
	}
}

// handleBeginStaging 在 staging 根下新建一个空目录并返回其绝对路径。由 nervud
// 建（而非 CLI 自选路径）保证：同一文件系统（安装期 renameat2 不 EXDEV）、属主/
// 权限受控（0700、属主 nervud）、且 install 的路径逃逸校验有明确判据。
//
// 顺便清扫陈旧 staging：CLI 若在 begin 之后、install 之前崩溃，会留下孤儿目录。
// 每次 begin 时best-effort删掉太老的（超过 staleStagingAge），不影响正确性、
// 只回收磁盘。
func (s *Server) handleBeginStaging() adminwire.Response {
	s.sweepStaleStaging()

	dir, err := os.MkdirTemp(s.stagingRoot, "stage-")
	if err != nil {
		s.audit("admin.BeginStaging", "", true, err, "mkdir temp staging")
		return failed("create staging dir: %v", err)
	}
	s.audit("admin.BeginStaging", dir, false, nil, "")
	return adminwire.Response{OK: true, Code: adminwire.CodeOK, StagingDir: dir}
}

// handleInstall 校验 staging 路径后触发 pkgregistry.Install。nervud 自己从 staging
// 目录读 manifest.json / manifest.sig 作为待验证字节，再由 Install 内部完整
// 验签 + digest 复核 + 裁决 + 原子提交。
func (s *Server) handleInstall(ctx context.Context, req adminwire.Request) adminwire.Response {
	staging, err := s.validateStagingChild(req.StagingDir)
	if err != nil {
		s.audit("admin.Install", req.StagingDir, true, err, "staging path rejected")
		return badRequest("%v", err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(staging, pkgregistry.ManifestFileName))
	if err != nil {
		s.cleanupStaging(staging)
		s.audit("admin.Install", staging, true, err, "read manifest")
		return badRequest("read %s: %v", pkgregistry.ManifestFileName, err)
	}
	sigBlock, err := os.ReadFile(filepath.Join(staging, pkgregistry.SignatureFileName))
	if err != nil {
		s.cleanupStaging(staging)
		s.audit("admin.Install", staging, true, err, "read signature")
		return badRequest("read %s: %v", pkgregistry.SignatureFileName, err)
	}

	entry, err := s.pkgs.Install(ctx, pkgregistry.InstallTransaction{
		ManifestBytes: manifestBytes,
		SigBlock:      sigBlock,
		StagingDir:    staging,
		Source:        pkgregistry.SourceDynamicInstall,
	})
	if err != nil {
		// Install 失败时 staging 目录未被 renameat2 消费（成功才会被移走），补偿删除
		// 这棵 CLI 解出的树，避免 staging 根堆积孤儿。安装本身的失败补偿（删已落盘的
		// 代码/数据孤儿）由 pkgregistry 内部负责，这里只清 staging。
		s.cleanupStaging(staging)
		s.audit("admin.Install", staging, true, err, "install")
		return failed("install: %v", err)
	}

	s.audit("admin.Install", entry.Manifest.PackageID, false, nil,
		fmt.Sprintf("version=%s trust=%s", entry.ActiveVersion, entry.Trust))
	info := entryToInfo(entry)
	return adminwire.Response{OK: true, Code: adminwire.CodeOK, Package: &info}
}

// handleUninstall 卸载一个 Package。系统镜像包不可动态卸载等规则由 pkgregistry 判定。
func (s *Server) handleUninstall(ctx context.Context, req adminwire.Request) adminwire.Response {
	if req.PackageID == "" {
		return badRequest("uninstall requires package_id")
	}
	if err := s.pkgs.Uninstall(ctx, req.PackageID); err != nil {
		s.audit("admin.Uninstall", req.PackageID, true, err, "")
		return classifyPkgErr(err)
	}
	s.audit("admin.Uninstall", req.PackageID, false, nil, "")
	return adminwire.Response{OK: true, Code: adminwire.CodeOK}
}

// handleList 列出当前已装 Package。
func (s *Server) handleList() adminwire.Response {
	entries := s.reg.List()
	infos := make([]adminwire.PackageInfo, 0, len(entries))
	for _, e := range entries {
		infos = append(infos, entryToInfo(e))
	}
	return adminwire.Response{OK: true, Code: adminwire.CodeOK, Packages: infos}
}

// handleSetEnabled 停用/启用一个 Component。保护名单/可停用性由 pkgregistry 判定。
func (s *Server) handleSetEnabled(ctx context.Context, req adminwire.Request) adminwire.Response {
	if req.PackageID == "" || req.ComponentID == "" {
		return badRequest("set-enabled requires package_id and component_id")
	}
	if err := s.pkgs.SetComponentEnabled(ctx, req.PackageID, req.ComponentID, req.Enabled); err != nil {
		s.audit("admin.SetComponentEnabled", req.PackageID, true, err,
			fmt.Sprintf("%s enabled=%v", req.ComponentID, req.Enabled))
		return classifyPkgErr(err)
	}
	s.audit("admin.SetComponentEnabled", req.PackageID, false, nil,
		fmt.Sprintf("%s enabled=%v", req.ComponentID, req.Enabled))
	return adminwire.Response{OK: true, Code: adminwire.CodeOK}
}

// handleSetPermission 设置一个运行期（GrantUser）权限的授予状态（grant/revoke）。
// 权限是否可运行期授予、撤销 motion 组的撤租联动，全由 permission.Registry 判定。
func (s *Server) handleSetPermission(req adminwire.Request) adminwire.Response {
	if req.PackageID == "" || req.Permission == "" {
		return badRequest("set-permission requires package_id and permission")
	}
	state, ok := grantStateFromWire(req.GrantState)
	if !ok {
		return badRequest("unknown grant state %q", req.GrantState)
	}
	if err := s.perms.SetRuntimeState(req.PackageID, req.Permission, state); err != nil {
		s.audit("admin.SetPermission", req.PackageID, true, err,
			fmt.Sprintf("%s=%s", req.Permission, req.GrantState))
		return failed("set permission: %v", err)
	}
	s.audit("admin.SetPermission", req.PackageID, false, nil,
		fmt.Sprintf("%s=%s", req.Permission, req.GrantState))
	return adminwire.Response{OK: true, Code: adminwire.CodeOK}
}

// ---- 校验与投影辅助 -------------------------------------------------------

// validateStagingChild 校验 dir 是 staging 根的直接子目录且当前存在为目录。
// 这是本模块唯一的路径安全职责：CLI 提交的 staging
// 路径必须是 nervud 之前经 begin-staging 发出的那类目录，不能是任意路径。用纯
// 字符串 path 运算（linux 语义）+ os.Lstat 拒 symlink 顶点，快速失败。
//
// 注意：这只是快速前置校验。真正把 staging 提交为代码目录的跨信任边界操作走
// authority 的 openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)，那才是最终保证。
func (s *Server) validateStagingChild(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("install requires staging_dir")
	}
	if !path.IsAbs(dir) {
		return "", fmt.Errorf("staging_dir %q must be absolute", dir)
	}
	clean := path.Clean(dir)
	if path.Dir(clean) != s.stagingRoot {
		return "", fmt.Errorf("staging_dir %q is not a direct child of staging root %q", clean, s.stagingRoot)
	}
	// 顶点不得是 symlink（防被诱导把别处的树当 staging 提交）。lstat 不跟随。
	fi, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("staging_dir %q: %v", clean, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("staging_dir %q is a symlink", clean)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("staging_dir %q is not a directory", clean)
	}
	return clean, nil
}

// cleanupStaging 尽力删掉一个 staging 目录（安装失败/元数据缺失时）。只在确认它
// 仍是 staging 根子目录时删 - 绝不因一个投递错误的路径而递归删到别处。
func (s *Server) cleanupStaging(dir string) {
	if path.Dir(path.Clean(dir)) != s.stagingRoot {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		s.log.Warn("admin: failed to clean staging dir", "dir", dir, "err", err)
	}
}

// entryToInfo 把 pkgregistry.Entry 投影成对外的 PackageInfo。
func entryToInfo(e pkgregistry.Entry) adminwire.PackageInfo {
	return adminwire.PackageInfo{
		ID:          e.Manifest.PackageID,
		Version:     e.ActiveVersion,
		VersionCode: e.VersionCode,
		Trust:       e.Trust.String(),
		Source:      e.Source.String(),
		Granted:     e.GrantedPermissions,
		Disabled:    e.DisabledComponents,
	}
}

// grantStateFromWire 把 wire 授予状态字符串映射为 permission.GrantState。
func grantStateFromWire(s string) (permission.GrantState, bool) {
	switch s {
	case adminwire.GrantStateNotRequested:
		return permission.GrantStateNotRequested, true
	case adminwire.GrantStateGranted:
		return permission.GrantStateGranted, true
	case adminwire.GrantStateDenied:
		return permission.GrantStateDenied, true
	case adminwire.GrantStateDeniedPermanent:
		return permission.GrantStateDeniedPermanent, true
	default:
		return 0, false
	}
}

// classifyPkgErr 把 pkgregistry 的错误归类到 wire Code：未安装/找不到组件类
// 归 CodeNotFound（供 CLI 给出更贴切的措辞/退出码），其余归 CodeFailed。
func classifyPkgErr(err error) adminwire.Response {
	code := adminwire.CodeFailed
	if errors.Is(err, pkgregistry.ErrPackageNotInstalled) || errors.Is(err, pkgregistry.ErrComponentNotFound) {
		code = adminwire.CodeNotFound
	}
	return adminwire.Response{OK: false, Code: code, Message: err.Error()}
}

func badRequest(format string, args ...any) adminwire.Response {
	return adminwire.Response{OK: false, Code: adminwire.CodeBadRequest, Message: fmt.Sprintf(format, args...)}
}

func failed(format string, args ...any) adminwire.Response {
	return adminwire.Response{OK: false, Code: adminwire.CodeFailed, Message: fmt.Sprintf(format, args...)}
}
