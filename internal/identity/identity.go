// 见 doc.go 的包说明
//
// 本文件是身份解析的核心：把内核给出的 SO_PEERCRED 凭证映射成一个可信的
// Caller。凭证本身由 internal/sysprobe 读取，本包不碰 syscall
package identity

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/nervus-os/nervud/internal/sysprobe"
)

var (
	// ErrUnknownUID 该 UID 没有对应任何已注册 Package
	//
	// 它必须与「UID 越界」区分开：越界是不变量违规（authority.CheckUID），
	// 而本错误表示区段合法但查无此包——通常是 Package 已被卸载而进程还活着，
	// 或者有人手工创建了一个落在 App 区段里的系统用户
	ErrUnknownUID = errors.New("identity: uid maps to no registered package")

	// ErrDuplicateUID 快照里有两个 Package 共用同一个 UID
	//
	// 这不是可以容忍的配置问题，而是安全地板塌了：架构 10.2 明确写着
	// 「如果让所有 Package 共用一个 UID，SO_PEERCRED 将无法提供 Package 级隔离，
	// 因此永远禁止」。一旦发生，UID 不再能唯一确定调用者是谁，本包的全部结论
	// 都失去意义，所以在装载快照时就拒绝，而不是等到解析时才发现
	ErrDuplicateUID = errors.New("identity: duplicate uid in package snapshot")

	// ErrDuplicateID 快照里有两个 UID 映射到同一个 Package ID
	//
	// 与 ErrDuplicateUID 对称的另一半：架构 9 要求 Package 与 UID 一一对应。
	// 只查 UID 唯一挡不住「同一个 Package ID 出现在两个 UID 下」——那会让
	// 权限归属、Endpoint 所有权和审计归因都指向一个有歧义的 Package
	ErrDuplicateID = errors.New("identity: duplicate package id in snapshot")
)

// TrustProfile 是信任与权限 profile
//
// 它不是第三种软件类型：只读系统镜像中的平台/OEM 签名 Package 才有资格获得
// 非 Ordinary 的 profile，动态安装的开发者签名 Package 即使声明了 Service
// 也仍然是 Ordinary。manifest 不能自封 system
type TrustProfile uint8

const (
	// TrustUnspecified 是零值，永远不是合法结论。
	// 与 proto 的 *_UNSPECIFIED = 0 同一个理由：漏填必须 fail closed，
	// 不能因为没赋值就默默拿到某个真实 profile
	TrustUnspecified TrustProfile = iota
	TrustOrdinary
	TrustOEM
	TrustPlatform
)

func (t TrustProfile) String() string {
	switch t {
	case TrustOrdinary:
		return "ordinary"
	case TrustOEM:
		return "oem"
	case TrustPlatform:
		return "platform"
	default:
		return "unspecified"
	}
}

// Valid 报告 t 是否为一个已定义的 profile
func (t TrustProfile) Valid() bool {
	return t == TrustOrdinary || t == TrustOEM || t == TrustPlatform
}

// Package 是身份解析所需的 Package 事实
//
// 只放解析身份用得着的字段。版本、文件清单、权限集合等属于 Package Registry，
// 不在这里复制一份——两份会漂
type Package struct {
	ID    string
	UID   uint32
	Trust TrustProfile
}

// Caller 是一条连接的可信身份
//
// UID/GID/PID 来自 Linux 内核，PackageID/Trust 来自 Registry 查表，
// 三者都不来自对端发来的任何字节
type Caller struct {
	PackageID string

	// ComponentID 在解析时为空：连接刚建立时只知道是哪个 Package，
	// 不知道是它的哪个 Component。它由握手阶段核对 Hello 的自报值后填入
	// （架构 10.2：nervud 验证声明，而不是相信声明）
	ComponentID string

	Trust TrustProfile

	UID uint32
	GID uint32

	// PID 会随进程退出被内核回收，仅供诊断与日志关联。
	// 不得在连接建立很久之后拿它去 /proc 反查并信任结果
	PID int32
}

// String 生成审计归因字符串，与 authority.Subject.String 的格式保持一致，
// 好让两个包写出的审计记录能被同一套离线分析规则处理
func (c Caller) String() string {
	if c.PackageID == "" {
		return "kernel"
	}
	return fmt.Sprintf("pkg:%s uid:%d", c.PackageID, c.UID)
}

// Registry 是 UID → Package 的索引
//
// 读多写少：每条新连接读一次，而写只发生在装包/卸载时。因此用写时复制 +
// 原子指针，读侧完全无锁——避免出现「装包正持写锁，所有新连接一起卡住」
//
// 零值不可用，必须经 NewRegistry 构造
type Registry struct {
	snap atomic.Pointer[snapshot]
}

type snapshot struct {
	byUID map[uint32]Package
}

func NewRegistry() *Registry {
	r := &Registry{}
	r.snap.Store(&snapshot{byUID: map[uint32]Package{}})
	return r
}

// Replace 原子替换整份索引
//
// 全量替换而不是增量改：Package Registry 提交事务后给出的是一个一致快照，
// 增量接口会诱使调用方做「先删后加」，而那两步之间存在一个 UID 查不到的窗口，
// 恰好落在窗口里的连接会被误判成未知 UID
//
// 校验失败时整份拒绝，旧快照保持不变——宁可继续用上一份已知良好的索引，
// 也不要装载一份自相矛盾的
func (r *Registry) Replace(pkgs []Package) error {
	next := make(map[uint32]Package, len(pkgs))
	seenID := make(map[string]uint32, len(pkgs))
	for _, p := range pkgs {
		switch {
		case p.ID == "":
			return fmt.Errorf("identity: package with uid %d has empty id", p.UID)
		case p.UID == 0:
			// UID 0 是 Linux 特殊 root 身份，App UID 0 永远禁止（架构 5）。
			// 这里再挡一次是因为 Registry 的内容来自安装流程，而安装流程的
			// 任何一处疏漏都不该让 root 变成一个可被解析出来的合法调用者
			return fmt.Errorf("identity: package %q has uid 0", p.ID)
		case !p.Trust.Valid():
			return fmt.Errorf("identity: package %q has invalid trust profile %d", p.ID, p.Trust)
		}
		if prev, dup := next[p.UID]; dup {
			return fmt.Errorf("%w: uid %d claimed by both %q and %q",
				ErrDuplicateUID, p.UID, prev.ID, p.ID)
		}
		if prevUID, dup := seenID[p.ID]; dup {
			return fmt.Errorf("%w: package %q maps to both uid %d and %d",
				ErrDuplicateID, p.ID, prevUID, p.UID)
		}
		next[p.UID] = p
		seenID[p.ID] = p.UID
	}
	r.snap.Store(&snapshot{byUID: next})
	return nil
}

// Lookup 按 UID 查 Package
//
// 无锁：一次原子 Load 加一次 map 查找。这条路径每建立一条连接走一次，
// 而 Package 数量是几十到低百的量级，整张表小到常驻 CPU 缓存
//
// 对未初始化的 Registry（未经 NewRegistry 的 &Registry{}，甚至 typed-nil）
// 一律当作空索引返回 not-found，而不是 panic。装配错误应当表现为「谁都不认识、
// 全部拒绝」这种 fail-safe 状态，绝不能让首个连接把整个 accept 路径打崩——
// 那会把一个装配 bug 放大成一次拒绝服务
func (r *Registry) Lookup(uid uint32) (Package, bool) {
	if r == nil {
		return Package{}, false
	}
	snap := r.snap.Load()
	if snap == nil {
		return Package{}, false
	}
	p, ok := snap.byUID[uid]
	return p, ok
}

// Len 返回当前索引里的 Package 数，供诊断与测试使用
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	snap := r.snap.Load()
	if snap == nil {
		return 0
	}
	return len(snap.byUID)
}

// Resolve 把内核凭证解析成可信身份
//
// 它只回答「这个 UID 属于哪个 Package」。UID 是否落在 App 区段内是
// authority.Invariants 的职责，由调用方在此之前完成——那条检查是系统级不变量，
// 不该在这里复制一份实现
func (r *Registry) Resolve(cred sysprobe.Ucred) (Caller, error) {
	p, ok := r.Lookup(cred.UID)
	if !ok {
		return Caller{}, fmt.Errorf("%w: uid %d", ErrUnknownUID, cred.UID)
	}
	return Caller{
		PackageID: p.ID,
		Trust:     p.Trust,
		UID:       cred.UID,
		GID:       cred.GID,
		PID:       cred.PID,
	}, nil
}
