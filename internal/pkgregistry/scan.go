// 见 doc.go 的包说明
//
// 本文件实现架构 §8 固定的启动扫描：只扫描两个受控来源，不递归扫描任意目录
//
//	/usr/lib/nervus/system-packages/*/manifest.json  系统镜像内置 Package
//	/var/lib/nervus/registry/                        nervud 自己提交、
//	  标记为 active 的动态安装版本索引
//
// 同时承担 §7/§9 要求的"每个 Package 一个稳定 UID"的持久化：UID 一旦分配，
// 写入 /var/lib/nervus/registry/ 下的记账文件，跨重启保持不变
package pkgregistry

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
)

const (
	// DefaultSystemPackagesDir 是只读系统镜像内置 Package 的固定来源
	DefaultSystemPackagesDir = "/usr/lib/nervus/system-packages"

	// DefaultRegistryStateDir 保存 Package Registry、活动版本和 UID 分配的
	// 可信状态；只有 nervud 可修改
	DefaultRegistryStateDir = "/var/lib/nervus/registry"

	allocatorStateFile = "_allocator.json"
)

// ScanResult 是一次启动扫描的结果
type ScanResult struct {
	Entries []Entry
	Skipped []SkippedPackage
}

// SkippedPackage 记录一个未能装载的 Package 及原因，供审计与诊断
type SkippedPackage struct {
	Path string
	Err  error
}

// Scan 执行一次完整的启动扫描
//
// packageRoot 通常取 authority.DefaultInvariants().PackageRoot；调用方
// 显式传入而不是本函数内部硬编码，便于测试用 t.TempDir() 隔离
func Scan(stateDir, systemPackagesDir, packageRoot string, log *slog.Logger) ScanResult {
	var result ScanResult

	sysEntries, sysSkipped := scanSystemImage(stateDir, systemPackagesDir, log)
	result.Entries = append(result.Entries, sysEntries...)
	result.Skipped = append(result.Skipped, sysSkipped...)

	dynEntries, dynSkipped := scanDynamicInstalls(stateDir, packageRoot, log)
	result.Entries = append(result.Entries, dynEntries...)
	result.Skipped = append(result.Skipped, dynSkipped...)

	return result
}

// scanSystemImage 扫描系统镜像内置 Package
//
// 信任来自"只读镜像 = 构建管线已经保证"这条 v1 简化：真实签名校验落地前，
// 存在于该目录即视为 TrustPlatform。真正的复核只做 digest——系统镜像本应
// 只读，digest 不符意味着镜像本身已损坏或被篡改，这是必须 fail-closed 的信号
//
// TODO(signature): 签名校验落地后，这里应改为调用 verifySignature 并按
// 其返回值决定 trust，而不是无条件给 TrustPlatform
func scanSystemImage(stateDir, systemPackagesDir string, log *slog.Logger) ([]Entry, []SkippedPackage) {
	var entries []Entry
	var skipped []SkippedPackage

	matches, err := filepath.Glob(filepath.Join(systemPackagesDir, "*", "manifest.json"))
	if err != nil {
		skipped = append(skipped, SkippedPackage{Path: systemPackagesDir, Err: err})
		return entries, skipped
	}

	for _, manifestPath := range matches {
		pkgDir := filepath.Dir(manifestPath)

		m, err := readManifest(manifestPath)
		if err != nil {
			skipped = append(skipped, SkippedPackage{Path: manifestPath, Err: err})
			continue
		}

		diff, err := VerifyDigests(pkgDir, m.Digests)
		if err != nil {
			skipped = append(skipped, SkippedPackage{Path: manifestPath, Err: err})
			continue
		}
		if !diff.Clean() {
			skipped = append(skipped, SkippedPackage{
				Path: manifestPath,
				Err:  fmt.Errorf("%w: %+v", ErrDigestMismatch, diff),
			})
			continue
		}

		uid, err := stableUID(stateDir, m.PackageID, m.Version, identity.TrustPlatform, SourceSystemImage)
		if err != nil {
			skipped = append(skipped, SkippedPackage{Path: manifestPath, Err: err})
			continue
		}

		if log != nil {
			log.Info("pkgregistry: loaded system package", "package_id", m.PackageID, "version", m.Version)
		}
		entries = append(entries, Entry{
			Manifest:      m,
			ActiveVersion: m.Version,
			UID:           uid,
			Trust:         identity.TrustPlatform,
			Source:        SourceSystemImage,
		})
	}
	return entries, skipped
}

// scanDynamicInstalls 读取此前 Install 提交并持久化的动态安装记账文件
//
// 信任不在这里重新裁决：Install 时 Arbitrate 已经把动态安装的 trust 定死为
// Ordinary（架构 §7：动态安装永远不能拿到系统权限 profile），boot 时重新
// 验证的是完整性（digest 是否被篡改），不是身份
func scanDynamicInstalls(stateDir, packageRoot string, log *slog.Logger) ([]Entry, []SkippedPackage) {
	var entries []Entry
	var skipped []SkippedPackage

	matches, err := filepath.Glob(filepath.Join(stateDir, "*.json"))
	if err != nil {
		skipped = append(skipped, SkippedPackage{Path: stateDir, Err: err})
		return entries, skipped
	}

	for _, statePath := range matches {
		if filepath.Base(statePath) == allocatorStateFile {
			continue
		}

		st, err := readRegistryState(statePath)
		if err != nil {
			skipped = append(skipped, SkippedPackage{Path: statePath, Err: err})
			continue
		}
		if st.Source != SourceDynamicInstall.String() {
			continue // 系统包的记账文件由 scanSystemImage 一侧处理
		}

		manifestPath := filepath.Join(packageRoot, st.PackageID, st.ActiveVersion, "manifest.json")
		m, err := readManifest(manifestPath)
		if err != nil {
			skipped = append(skipped, SkippedPackage{Path: manifestPath, Err: err})
			continue
		}

		diff, err := VerifyDigests(filepath.Dir(manifestPath), m.Digests)
		if err != nil {
			skipped = append(skipped, SkippedPackage{Path: manifestPath, Err: err})
			continue
		}
		if !diff.Clean() {
			skipped = append(skipped, SkippedPackage{
				Path: manifestPath,
				Err:  fmt.Errorf("%w: %+v", ErrDigestMismatch, diff),
			})
			continue
		}

		if log != nil {
			log.Info("pkgregistry: loaded dynamic package", "package_id", m.PackageID, "version", m.Version)
		}
		entries = append(entries, Entry{
			Manifest:           m,
			ActiveVersion:      st.ActiveVersion,
			UID:                st.UID,
			Trust:              identity.TrustOrdinary,
			Source:             SourceDynamicInstall,
			GrantedPermissions: st.GrantedPermissions,
		})
	}
	return entries, skipped
}

func readManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("pkgregistry: read manifest %s: %w", path, err)
	}
	return ParseManifest(data)
}

// stableUID 返回 packageID 已持久化的 UID；若这是第一次见到该 Package，
// 分配一个新的并原子写入记账文件
func stableUID(stateDir, packageID, version string, trust identity.TrustProfile, src Source) (uint32, error) {
	existing, err := readRegistryState(stateFilePath(stateDir, packageID))
	if err == nil {
		return existing.UID, nil
	}
	if !os.IsNotExist(err) {
		return 0, err
	}

	uid, err := allocateUID(stateDir)
	if err != nil {
		return 0, err
	}
	st := registryState{
		PackageID:     packageID,
		ActiveVersion: version,
		UID:           uid,
		Trust:         trust.String(),
		Source:        src.String(),
	}
	if err := saveRegistryState(stateDir, st); err != nil {
		return 0, err
	}
	return uid, nil
}

// ---- 记账文件（每 Package 一个 JSON 文件）------------------------------

type registryState struct {
	PackageID     string `json:"package_id"`
	ActiveVersion string `json:"active_version"`
	UID           uint32 `json:"uid"`
	Trust         string `json:"trust"`
	Source        string `json:"source"`
	// GrantedPermissions 是 Install 时 permission.Intersect 算出的授予集合，
	// 随记账文件持久化；scanDynamicInstalls 启动时直接读回，不重新裁决
	// （见 module.go 顶部"trust 和 grant 的裁决只在 Install 时做一次"）
	GrantedPermissions []string `json:"granted_permissions,omitempty"`
}

func stateFilePath(dir, packageID string) string {
	return filepath.Join(dir, packageID+".json")
}

func readRegistryState(path string) (registryState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return registryState{}, err // 调用方按 os.IsNotExist 区分"从未见过"与真正的 I/O 错误
	}
	var st registryState
	if err := json.Unmarshal(data, &st); err != nil {
		return registryState{}, fmt.Errorf("pkgregistry: decode state %s: %w", path, err)
	}
	return st, nil
}

func saveRegistryState(dir string, st registryState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("pkgregistry: encode state for %s: %w", st.PackageID, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("pkgregistry: create registry state dir %s: %w", dir, err)
	}
	return writeFileAtomic(stateFilePath(dir, st.PackageID), data, 0o644)
}

// ---- UID 分配器 -----------------------------------------------------------

type allocatorState struct {
	NextUID uint32 `json:"next_uid"`
}

// allocateUID 分配下一个稳定 Package UID，持久化在 dir/_allocator.json
//
// v1 简化：只做高水位单调分配，从不回收复用已释放的 UID。这是"卸载后不能
// 立即不安全地复用"这条架构要求（§9）最简单的安全实现——代价是 UID 空间
// 用一个少一个，真正的"冷却期后回收"策略留给后续设计，此刻用简单换安全
func allocateUID(dir string) (uint32, error) {
	inv := authority.DefaultInvariants()
	path := filepath.Join(dir, allocatorStateFile)

	next := inv.MinAppUID
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st allocatorState
		if uerr := json.Unmarshal(data, &st); uerr != nil {
			return 0, fmt.Errorf("pkgregistry: decode allocator state: %w", uerr)
		}
		if st.NextUID > next {
			next = st.NextUID
		}
	case os.IsNotExist(err):
		// 第一次分配，从 MinAppUID 开始
	default:
		return 0, fmt.Errorf("pkgregistry: read allocator state: %w", err)
	}

	if next > inv.MaxAppUID {
		return 0, fmt.Errorf("pkgregistry: uid space exhausted (max %d)", inv.MaxAppUID)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("pkgregistry: create registry state dir %s: %w", dir, err)
	}
	out, err := json.MarshalIndent(allocatorState{NextUID: next + 1}, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("pkgregistry: encode allocator state: %w", err)
	}
	if err := writeFileAtomic(path, out, 0o644); err != nil {
		return 0, err
	}
	return next, nil
}

// writeFileAtomic 把 data 原子写入 path：先写同目录下的临时文件再 rename，
// 避免半写状态在 crash 或并发读者眼里出现
//
// 这是标准库 os 的普通文件 I/O，不涉及 depguard 限制的 syscall/x-sys/os-exec
// 三个包——pkgregistry 自己的记账状态不需要过 Authority Gate，Gate 只用于
// 跨信任边界的操作（把 staging 提交成最终代码目录、创建属于某 UID 的私有
// 数据目录），见 install.go
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("pkgregistry: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Rename 成功后 tmpPath 已不在原处，这里的 Remove 会失败，忽略即可；
	// 只有在 Rename 之前失败退出的路径上，这个 defer 才真正负责清理
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("pkgregistry: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("pkgregistry: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pkgregistry: close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("pkgregistry: chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("pkgregistry: rename into place: %w", err)
	}
	return nil
}
