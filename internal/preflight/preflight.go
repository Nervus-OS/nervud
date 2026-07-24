//go:build linux

// Package preflight 是 nervud 装配最早期的一次文件系统自检。
//
// 它区分两类路径，处理相反：
//
//   - 只读镜像区（/usr/libexec/nervus/nervud、/usr/lib/nervus/*、/usr/share/nervus/trust）：
//     只检查，绝不修改。不符即返回 fatal error，装配中止、内核不启动。
//     这些路径的正确性是镜像完整性的一部分 - 若 /usr/share/nervus/trust 已经
//     world-writable，说明镜像已被破坏，自动 chmod 回去只是掩盖入侵痕迹。正确
//     反应是拒绝启动 + 报警，与半死的 TCB 比重启更危险同逻辑。
//
//   - nervud 自有可写区（/var/lib/nervus/*、/run/nervus/）：检查 + 主动设定。
//     缺失即创建，权限不符即 chmod 回期望值。但若某路径已存在且属主不是
//     nervud 自身，说明有非特权进程抢先创建（squat） - 此时不 chown 洗白它，
//     而是 fatal（ 对 /run/nervus 的明确要求）。
//
// 为什么是独立包而非 authority 操作：authority.Gate 收敛的是跨信任边界的运行期
// 特权操作（把 staging 提交为代码、创建属于某 App UID 的私有目录）。preflight 是
// 内核给自己的地基做一次性开机自检，发生在任何模块 Start 之前、任何 App 连上
// 之前，不跨信任边界。属主/权限的读取走 sysprobe（纯观察），创建/修正走标准库 os
// （depguard 允许），都不需要 authority 的窄操作模型。
package preflight

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/sysprobe"
)

// ErrPreflight 是任何 preflight 检查失败的哨兵。装配层据此中止启动
var ErrPreflight = errors.New("preflight: filesystem self-check failed")

// entryKind 是一个受检路径应当是的文件类型
type entryKind uint8

const (
	kindDir entryKind = iota
	kindFile
)

// Rule 是对单个路径的检查规则
type Rule struct {
	Path string
	Kind entryKind
	// Perm 是期望的权限低 12 位（含 setuid/setgid/sticky）。
	// PermExact=true 时要求精确相等；false 时只要求 group/other 不可写（w 位为 0）
	Perm      uint32
	PermExact bool
	// Writable=false 只读区（只查、不符即 fatal）；true 可写区（缺失则建、权限不符则修）
	Writable bool
}

// Config 是一次 preflight 的输入
//
// OwnerUID/OwnerGID 参数化是为了可测：生产恒为 nervud 自身（通常 root，即
// os.Geteuid==0），测试用 t.TempDir 时注入当前 uid/gid 走完整条路径
type Config struct {
	Rules    []Rule
	OwnerUID uint32
	OwnerGID uint32
	Log      *slog.Logger
}

// DefaultConfig 是生产镜像的固定规则集（ + 路径表）
//
// PackageRoot/DataRoot 从 authority.DefaultInvariants 取，避免与 authority
// 各持一份路径常量而漂移；其余固定路径按 硬编码
func DefaultConfig(log *slog.Logger) Config {
	inv := authority.DefaultInvariants()
	return Config{
		OwnerUID: uint32(os.Geteuid()),
		OwnerGID: uint32(os.Getegid()),
		Log:      log,
		Rules: []Rule{
			// ---- 只读镜像区：只检查，不符 fatal ----
			// nervud 二进制：属主 root，group/other 不可写（不强求精确 0o755，
			// 允许 0o755 或更严的 0o555，只堵住可写）
			{Path: "/usr/libexec/nervus/nervud", Kind: kindFile, Perm: 0, PermExact: false, Writable: false},
			{Path: "/usr/lib/nervus/system-packages", Kind: kindDir, Perm: 0o755, PermExact: true, Writable: false},
			{Path: "/usr/lib/nervus/jre", Kind: kindDir, Perm: 0o755, PermExact: true, Writable: false},
			{Path: "/usr/share/nervus/trust", Kind: kindDir, Perm: 0o755, PermExact: true, Writable: false},

			// ---- nervud 自有可写区：检查 + 主动设定（父目录在前，子目录在后）----
			{Path: "/var/lib/nervus", Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true},
			{Path: "/var/lib/nervus/registry", Kind: kindDir, Perm: 0o700, PermExact: true, Writable: true},
			{Path: "/var/lib/nervus/packages", Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true},
			// 动态安装 staging 根：nervusctl/安装器解包 .nspkg 的落点，随后由 nervud
			// 经 renameat2 提交进 PackageRoot（同处 /var/lib/nervus = 同一文件系统）。
			// 0700 且属主为 nervud，避免装包中间态被其它进程读取或篡改
			{Path: "/var/lib/nervus/staging", Kind: kindDir, Perm: 0o700, PermExact: true, Writable: true},
			{Path: inv.PackageRoot, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true},
			{Path: inv.DataRoot, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true},
			{Path: "/var/lib/nervus/jvm-cache", Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true},
			// /run 是 tmpfs，chattr +i 不被支持；等价保护是父目录 sticky：01755 让
			// 非 root 进程无法在其中 create/unlink 任何条目，socket 就删不掉、换不掉
			{Path: "/run/nervus", Kind: kindDir, Perm: 0o1755, PermExact: true, Writable: true},
		},
	}
}

// Run 依次执行全部规则。任一只读区规则不符、或任一可写区路径被非法占用，
// 即返回 ErrPreflight（fatal）；可写区的缺失/权限偏差会被就地修正后放行
func Run(cfg Config) error {
	for _, r := range cfg.Rules {
		if err := cfg.apply(r); err != nil {
			return err
		}
	}
	if cfg.Log != nil {
		cfg.Log.Info("preflight: filesystem self-check passed", "rules", len(cfg.Rules))
	}
	return nil
}

func (cfg Config) apply(r Rule) error {
	st, err := sysprobe.LstatPath(r.Path)
	notExist := errors.Is(err, fs.ErrNotExist)

	switch {
	case err != nil && !notExist:
		// 真正的 I/O 错误（权限不足、损坏） - 两类区都无法继续
		return fmt.Errorf("%w: stat %s: %v", ErrPreflight, r.Path, err)

	case notExist:
		if !r.Writable {
			// 只读镜像区缺失 = 镜像不完整，绝不代建
			return fmt.Errorf("%w: required read-only path %s is missing", ErrPreflight, r.Path)
		}
		return cfg.create(r)

	default:
		return cfg.verify(r, st)
	}
}

// verify 对已存在的路径核对类型/属主/权限；可写区在权限不符时就地修正
func (cfg Config) verify(r Rule, st sysprobe.PathStat) error {
	// 任何区：根位置被换成 symlink 都是危险信号（只读区=镜像被动手脚；
	// 可写区=被诱导写到别处）。lstat 已不跟随，这里据实拒绝
	if st.IsSymlink {
		return fmt.Errorf("%w: %s is a symlink", ErrPreflight, r.Path)
	}
	if r.Kind == kindDir && !st.IsDir {
		return fmt.Errorf("%w: %s is not a directory", ErrPreflight, r.Path)
	}
	if r.Kind == kindFile && !st.IsRegular {
		return fmt.Errorf("%w: %s is not a regular file", ErrPreflight, r.Path)
	}
	if st.UID != cfg.OwnerUID {
		// 只读区：镜像属主错乱。可写区：非 nervud 进程抢建（squat） - 不 chown
		// 洗白其内容，直接 fatal（ 对 /run/nervus 的明确要求，推广到全部可写区）
		return fmt.Errorf("%w: %s owned by uid %d, want %d", ErrPreflight, r.Path, st.UID, cfg.OwnerUID)
	}

	if !cfg.permOK(r, st.Perm) {
		if !r.Writable {
			return fmt.Errorf("%w: read-only path %s has perm %#o (want %s)",
				ErrPreflight, r.Path, st.Perm, describePerm(r))
		}
		// 可写区：就地修正到期望权限
		if err := os.Chmod(r.Path, fileMode(r.Perm)); err != nil {
			return fmt.Errorf("%w: chmod %s: %v", ErrPreflight, r.Path, err)
		}
		if cfg.Log != nil {
			cfg.Log.Warn("preflight: corrected permissions on writable path",
				"path", r.Path, "was", fmt.Sprintf("%#o", st.Perm), "now", fmt.Sprintf("%#o", r.Perm))
		}
	}
	return nil
}

// create 建立缺失的可写区目录并设定属主/权限
func (cfg Config) create(r Rule) error {
	// MkdirAll 容忍父目录已存在；叶子权限受 umask 削减，随后显式 chmod 回写。
	// 父目录（若本轮才由 MkdirAll 建出）也各自在自己的规则里被 chmod 到期望值，
	// 因为规则表里父在子前
	if err := os.MkdirAll(r.Path, 0o755); err != nil {
		return fmt.Errorf("%w: mkdir %s: %v", ErrPreflight, r.Path, err)
	}
	if err := os.Chmod(r.Path, fileMode(r.Perm)); err != nil {
		return fmt.Errorf("%w: chmod %s: %v", ErrPreflight, r.Path, err)
	}
	if err := os.Chown(r.Path, int(cfg.OwnerUID), int(cfg.OwnerGID)); err != nil {
		return fmt.Errorf("%w: chown %s: %v", ErrPreflight, r.Path, err)
	}
	if cfg.Log != nil {
		cfg.Log.Info("preflight: created writable path", "path", r.Path, "perm", fmt.Sprintf("%#o", r.Perm))
	}
	return nil
}

// permOK 报告实际权限 perm 是否满足规则
func (cfg Config) permOK(r Rule, perm uint32) bool {
	if r.PermExact {
		return perm == r.Perm
	}
	// 非精确：只要求 group/other 不可写
	return perm&0o022 == 0
}

func describePerm(r Rule) string {
	if r.PermExact {
		return fmt.Sprintf("%#o", r.Perm)
	}
	return "group/other not writable"
}

// fileMode 把 unix 原始权限位（含 0o1000 sticky / 0o2000 setgid / 0o4000 setuid）
// 转成 os.FileMode。os.Chmod 里 sticky/setuid/setgid 用的是 ModeSticky 等高位标志，
// 不是 unix 的 0o7000 低位，必须显式映射，否则 01755 会被当成 0755 丢掉 sticky
func fileMode(raw uint32) os.FileMode {
	m := os.FileMode(raw & 0o777)
	if raw&0o1000 != 0 {
		m |= os.ModeSticky
	}
	if raw&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if raw&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	return m
}
