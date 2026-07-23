// 见 doc.go 的包说明
//
// 本文件定义租约句柄与租约本体。Lease 是【不可变值】：签发后任何字段都不再改动，
// 续租产生一个新值整体替换（deadline 变、ID 不变），因此读侧可以一次原子 Load 拿到
// 一个自洽快照，不必担心读到半改状态
package control

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/motiongate"
)

// ResourceBaseMain 是 [REWRITE-v1] 唯一合法的执行器 Resource
//
// 申请里的 Resource 不等于它即拒绝，【不做静默降级】：静默把未知 Resource 当成
// base.main，会在 v2 放开多 Resource 时变成静默错配——申请方以为拿到了手臂的控制权，
// 实际拿到的是底盘的
const ResourceBaseMain = "base.main"

// ID 是系统签发的不透明租约句柄（NRCP §10.2 的 lease_id）
//
// 定长数组而不是 string：值类型可比较、可放进不可变 Lease，且比较与拷贝都不产生堆
// 分配——Check 在每条运动命令上比对它，必须零分配
type ID [16]byte

// String 返回十六进制形式，供审计与诊断。只在非热路径调用（会分配）
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// newID 生成一个不可预测的租约句柄
//
// 不用自增计数器：句柄要求不透明，可预测的句柄会让「猜一个 lease_id 试试」变成一条
// 值得尝试的攻击路径。crypto/rand.Read 在当前 Go 版本永不返回错误（熵源失败时它自己
// panic），因此这里没有错误分支——真的取不到熵时崩溃退出，比签出一个可预测句柄安全
func newID() ID {
	var id ID
	_, _ = rand.Read(id[:])
	return id
}

// ConnID 是租约绑定的连接/远程会话句柄（NRCP §10.2 的 owner_connection）
//
// 由 IPC 侧在连接准入时铸造并保证进程内唯一；0 永远非法，用作「未设置」哨兵。
// 租约不能转让：所有操作都要求同时给出 ID 与 ConnID，两者都对上才认
type ConnID uint64

// Lease 是一次已签发的控制租约（NRCP §10.2）
//
// 不可变：签发后不再原地修改任何字段
type Lease struct {
	ID    ID
	Conn  ConnID
	Class Class

	// Resource [REWRITE-v1] 恒为 ResourceBaseMain。保留字段而不是省掉，是因为
	// 语义上租约从第一天就是 Resource-scoped，v2 放开时不必改结构与调用方
	Resource string

	// Owner 是签发时的可信调用者身份，仅用于审计归因；权限复核不读它
	// （权限是动态的，每次调用要重新查，见 permission.Registry.Allowed 的说明）
	Owner identity.Caller

	IssuedAt time.Time
	Deadline time.Time

	// TTL 是本租约每次续租延长的时长。记在租约里而不是每次回头查 Policy：申请方
	// 可以要一个比 Policy 上限更短的 TTL，续租必须沿用它，否则续着续着就自己变长了
	TTL time.Duration

	// Epoch 是签发时的 motion epoch。任何撤销边界都会递增 Gate 的 epoch，因此
	// 「lease.Epoch != gate.Epoch」本身就是一条 fail-closed 的失效判据——即便撤销
	// 动作因故没跑完，陈旧租约也授权不了运动
	Epoch uint64

	// Deadman 是命令新鲜度窗口，0 表示本租约不要求 deadman。
	// 超过该窗口没有新鲜输入即撤租、epoch 递增、回到 NONE（NRCP §10.5）
	Deadman time.Duration
}

// Snapshot 是控制面的一致只读快照，供诊断与未来的 IPC 观察面使用
type Snapshot struct {
	// Source 是有效控制来源。Safety 非 NORMAL 时恒为 SourceSafety，
	// 与是否还残留着一条租约无关（Agent 文档 §3.3 的判定顺序）
	Source Source

	State motiongate.State
	Epoch uint64

	// Held 为 false 时 Lease 是零值（当前为 NONE）
	Held  bool
	Lease Lease
}
