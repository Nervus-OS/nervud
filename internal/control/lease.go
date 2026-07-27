// 本文件定义租约句柄与租约本体。Lease 是不可变值：签发后任何字段都不再改动，
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

// ResourceBaseMain 是协议隐式默认与 legacy ControlSnapshot 的底盘句柄。
// 其它已由 catalog 解析的非空 handle 无需在 control 中新增常量或分支。
const ResourceBaseMain = "base.main"

// ID 是系统签发的不透明租约句柄（ 的 lease_id）
//
// 定长数组而不是 string：值类型可比较、可放进不可变 Lease，且比较与拷贝都不产生堆
// 分配 - Check 在每条运动命令上比对它，必须零分配
type ID [16]byte

// String 返回十六进制形式，供审计与诊断。只在非热路径调用（会分配）
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// newID 生成一个不可预测的租约句柄
//
// 不用自增计数器：句柄要求不透明，可预测的句柄会让猜一个 lease_id 试试变成一条
// 值得尝试的攻击路径。crypto/rand.Read 在当前 Go 版本永不返回错误（熵源失败时它自己
// panic），因此这里没有错误分支 - 真的取不到熵时崩溃退出，比签出一个可预测句柄安全
func newID() ID {
	var id ID
	_, _ = rand.Read(id[:])
	return id
}

// ConnID 是租约绑定的连接/远程会话句柄（ 的 owner_connection）
//
// 由 IPC 侧在连接准入时铸造并保证进程内唯一；0 永远非法，用作未设置哨兵。
// 租约不能转让：所有操作都要求同时给出 ID 与 ConnID，两者都对上才认
type ConnID uint64

// Lease 是一次已签发的控制租约
//
// 不可变：签发后不再原地修改任何字段
type Lease struct {
	ID    ID
	Conn  ConnID
	Class Class

	// Resource 是 catalog 已解析的稳定公开 handle；每个 handle 有独立租约槽。
	Resource string
	// ResourceGeneration pins the exact catalog definition that authorized this
	// lease. A stable handle may be reused after an upgrade, but old authority
	// must never carry into the replacement definition.
	ResourceGeneration uint64

	// Owner 是签发时的可信调用者身份，仅用于审计归因；权限复核不读它
	// （权限是动态的，每次调用要重新查，见 permission.Registry.Allowed 的说明）
	Owner identity.Caller

	IssuedAt time.Time
	Deadline time.Time

	// TTL 是本租约每次续租延长的时长。记在租约里而不是每次回头查 Policy：申请方
	// 可以要一个比 Policy 上限更短的 TTL，续租必须沿用它，否则续着续着就自己变长了
	TTL time.Duration

	// Epoch 是签发时从全局 motion epoch 分配器取得的单调 token。普通边界只撤同一
	// Resource；Safety Trip 的 token 是跨 Resource floor，旧 token 全部失效。
	Epoch uint64

	// Deadman 是命令新鲜度窗口，0 表示本租约不要求 deadman。
	// 超过该窗口没有新鲜输入即撤租、epoch 递增、回到 NONE
	Deadman time.Duration
}

// Snapshot 是控制面的一致只读快照，供诊断与未来的 IPC 观察面使用
type Snapshot struct {
	// Source 是有效控制来源。Safety 非 NORMAL 时恒为 SourceSafety，
	// 因为锁存状态必须优先于任何仍残留的租约
	Source Source

	State motiongate.State
	// Epoch 是采样时的全局 motion token 分配器值；多资源下可以大于 Lease.Epoch。
	Epoch uint64

	// Held 为 false 时 Lease 是零值（当前为 NONE）
	Held  bool
	Lease Lease
}
