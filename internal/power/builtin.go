// 本包把整机电源动作（有序重启 / 关机）包成一个【内建 endpoint】的 handler，
// 供 nervud 在装配期注册（endpoint.RegisterBuiltin）。
//
// # 为什么是内建 endpoint 而不是新的 Envelope body
//
// envelope.proto 的规矩：「想加一个新 body 之前先问，它是否属于建立连接 / 发现
// endpoint / 发起调用 / 返回结果 / 取消 / 订阅 / 推送事件 / 维持连接这八件事之一；
// 不是就应该做成某个 Interface 的 method。」关机不属于其中任何一件。
//
// 而它又不可能由外部 Provider 提供——真正执行的是 Authority Gate，只有 nervud
// 有那个权限。所以走内建：调用方用完全标准的 Resolve + Request 访问，
// 不知道也不需要知道对面是内核还是 Provider。与 safety.control 同一形态。
//
// # 方法 ID 为什么是手写常量
//
// safety 那边从 proto 生成的枚举取 method_id，明确不在本地重抄——抄一份会悄悄
// 过期。这里做不到：本接口还没有对应的 .proto。
//
// 于是取舍是【手写 + 两侧交叉引用】：本文件的常量是唯一定义，Kotlin 侧
// （nervus-system-software 的 settings-app/PowerClient.kt）注释里指回这里。
// v2 补上 power_control.proto 之后，这里应当立刻改成从生成的枚举取值，
// 并把 Kotlin 侧一并切过去。在那之前，改动其中任何一侧都必须同步改另一侧，
// 否则症状是「点了没反应」——调用被路由到一个不存在的方法，回 NOT_FOUND。
package power

import (
	"context"
	"fmt"
	"log/slog"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
)

// BuiltinInterfaceID 是本内建接口的 ID。
//
// 必须与两处一致：endpoint.DefaultInterfaceCatalog 里的条目（那里定门槛），
// 以及调用方 manifest 的 interfaces 声明
const BuiltinInterfaceID = "nervus.interface.power"

// 方法 ID。理由见文件头
const (
	// MethodReboot 有序重启。请求与响应都是空 payload
	MethodReboot uint32 = 1
	// MethodPowerOff 有序关机。请求与响应都是空 payload
	MethodPowerOff uint32 = 2
)

// Gate 是本包对 authority 的窄接口依赖
type Gate interface {
	Power(ctx context.Context, subj authority.Subject, req authority.PowerRequest) error
}

// Module 持有执行电源动作所需的最小依赖
type Module struct {
	gate Gate
	log  *slog.Logger
}

// New 构造 Module。gate 为 nil 时 handler 一律 fail-closed 回 UNAVAILABLE
func New(gate Gate, log *slog.Logger) *Module {
	return &Module{gate: gate, log: log}
}

// BuiltinHandler 返回可直接交给 endpoint.RegisterBuiltin 的处理函数。
func (m *Module) BuiltinHandler() endpoint.BuiltinHandler {
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		var payload []byte
		var code ipcv1.StatusCode
		switch call.MethodID {
		case MethodReboot:
			payload, code = m.act(call.Context, call.Caller, authority.PowerActionReboot)
		case MethodPowerOff:
			payload, code = m.act(call.Context, call.Caller, authority.PowerActionPowerOff)
		default:
			// fail closed：没实现的方法就是不存在。静默成功会让调用方以为
			// 机器要关了，然后一直等一个永远不会发生的关机
			code = ipcv1.StatusCode_STATUS_CODE_NOT_FOUND
		}
		return endpoint.BuiltinResult{Payload: payload, Code: code}
	}
}

func (m *Module) act(ctx context.Context, caller identity.Caller, action authority.PowerAction) ([]byte, ipcv1.StatusCode) {
	if m == nil || m.gate == nil {
		return nil, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	}

	// Subject 用调用方而不是 kernel：审计要回答的是「谁把机器关了」。
	// Gate 内部的 osPower 另有一条 Subject=kernel 的 intent 记录，那条回答的是
	// 「关机确实开始了」——两条各管一头，都需要
	subj := authority.Subject{PackageID: caller.PackageID, UID: caller.UID}
	req := authority.PowerRequest{
		Action: action,
		// Reason 是 Validate 的必填项。这条路径上的理由就是「用户从某个包发起的」，
		// 把包 ID 写进去，事后能直接对上是设置还是别的什么发的
		Reason: fmt.Sprintf("requested by %s", subj.String()),
	}

	if err := m.gate.Power(ctx, subj, req); err != nil {
		if m.log != nil {
			m.log.Warn("power: action failed", "action", action.String(), "caller", subj.String(), "err", err)
		}
		return nil, ipcv1.StatusCode_STATUS_CODE_INTERNAL
	}

	// 走到这里通常意味着 systemd 已经接下了停机流程，本进程随时会被 SIGTERM。
	// 仍然返回 OK：调用方可能在极短的窗口里收到它，收到了就该显示「正在关机」
	return nil, ipcv1.StatusCode_STATUS_CODE_OK
}
