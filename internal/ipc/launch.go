// 本文件是"启动组件"的 wire 接线: 把 Envelope 的 LaunchComponent(80) 接到
// internal/service 的 EnsureStarted 上.
//
// # 为什么需要一条独立的消息
//
// 在此之前, 内核里唯一能拉起组件的路径是 endpoint.Resolve 拉起 on-demand
// 提供者. 于是"启动一个 App"只能被迫写成"对它导出的某个接口发一次
// ResolveEndpoint", 代价有三:
//
//  1. 每个可启动的 App 都得导出一个自己根本不需要的占位接口;
//  2. "解析接口"与"启动应用"共用一条消息, 审计里分不开 - 排查
//     "谁把这个东西拉起来的"时看到的全是 ResolveEndpoint;
//  3. 一个没有任何接口的纯 UI 应用没有任何办法被启动.
//
// # 它不建立任何调用关系
//
// 成功只意味着"那个组件现在在跑". 调用方想和它通信仍要走 ResolveEndpoint,
// 该有的权限与可见性裁决一条不少 - 不因为"是我启动的它"而放松.
package ipc

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/service"
)

// permSystemLaunch 是发起 LaunchComponent 所需的权限.
//
// 与中央 catalog bootstrap 里的条目必须同名 - 那边是定义, 这里是执法点.
// 不是普通应用该有的能力: 能任意拉起组件意味着能绕过 on-demand 的节能语义,
// 也能把一个刚被停用又启用的组件立刻拉起. v1 只给 Launcher 与会话服务.
const permSystemLaunch = "perm.system.launch"

// permPermissionAdmin 是系统确认 UI 的身份凭据.
//
// 它 SYSTEM_ONLY + PLATFORM 信任 + platform-release 签名角色 (见 catalog
// bootstrap), 因此持有者只可能是随只读系统镜像发布的那一个确认 UI.
// 本包只用它回答"这次调用是不是确认 UI 发起的", 见 conn.callerIsConfirmationUI
const permPermissionAdmin = "perm.permission.admin"

// callerIsConfirmationUI 回答本连接的调用方是不是系统确认 UI.
//
// permission 未接线时 (最小装配/测试) 返回 false - 这一问必须 fail-closed:
// 认错了等于让任意调用方直接触发需用户确认的操作
func (co *conn) callerIsConfirmationUI() bool {
	if co == nil || co.s == nil || co.s.permission == nil {
		return false
	}
	return co.s.permission.Allowed(co.caller.PackageID, permPermissionAdmin)
}

// handleLaunchComponent 处理一次启动请求.
func (co *conn) handleLaunchComponent(req *ipcv1.LaunchComponent) bool {
	reqID := req.GetRequestId()
	if reqID == 0 {
		co.log.Warn("ipc: LaunchComponent with reserved request_id 0, closing")
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}

	if co.s.launcher == nil {
		// service 未接线 (测试/裁剪构建). 回 UNAVAILABLE 而不是关连接:
		// 能力缺口不是协议违规. 与 leases == nil 的降级同一形态
		return co.enqueue(launchFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_SPAWN_FAILED))
	}

	// 权限: 在做任何查表之前先拦. 放在后面的话, 一个无权调用方仍能靠
	// "NOT_FOUND 还是 PERMISSION_DENIED"的差别探测出机器上装了哪些包
	if co.s.permission == nil || !co.s.permission.Allowed(co.caller.PackageID, permSystemLaunch) {
		co.s.auditViolation(co.caller, errLaunchDenied)
		return co.enqueue(launchFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_UNSPECIFIED))
	}

	pkg := req.GetPackageId()
	comp := req.GetComponentId()
	if pkg == "" || comp == "" {
		// 两者都必填. 不做"component 留空 = 该包唯一的 app 组件"这类推断:
		// 一个包完全可能有多个 app 组件, 推断规则会在它从一个变成两个的那天
		// 悄悄改变行为
		return co.enqueue(launchFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_UNSPECIFIED))
	}

	// 先问在不在跑: EnsureStarted 本身幂等, 但调用方需要知道自己是不是那个
	// 真正把它拉起来的人 (会话服务据此决定要不要记一条"桌面重启了")
	alreadyRunning := co.s.launcher.IsRunning(pkg, comp)

	if err := co.s.launcher.EnsureStarted(context.Background(), pkg, comp); err != nil {
		code, reason := launchErrorToWire(err)
		co.s.auditViolation(co.caller, err)
		return co.enqueue(launchFailure(reqID, code, reason))
	}

	co.s.auditLaunch(co.caller, pkg, comp, alreadyRunning)
	return co.enqueue(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_LaunchComponentResult{
			LaunchComponentResult: &ipcv1.LaunchComponentResult{
				RequestId: reqID,
				Outcome: &ipcv1.LaunchComponentResult_Success{
					Success: &ipcv1.LaunchComponentSuccess{AlreadyRunning: alreadyRunning},
				},
			},
		},
	})
}

var errLaunchDenied = errors.New("ipc: launch denied: missing " + permSystemLaunch)

// launchErrorToWire 把 service 层的错误映射成 (StatusCode, reason).
//
// 用 errors.Is 对哨兵值判断而不是匹配错误字符串: 字符串匹配会在有人改一句
// 中文错误信息时静默失效, 而失效的表现是所有失败都归一成 SPAWN_FAILED,
// "组件被停用"这类可操作的原因就消失了.
func launchErrorToWire(err error) (ipcv1.StatusCode, ipcv1.LaunchComponentReason) {
	switch {
	case errors.Is(err, service.ErrUnknownPackage):
		return ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_PACKAGE_NOT_FOUND
	case errors.Is(err, service.ErrUnknownComponent):
		return ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_COMPONENT_NOT_FOUND
	case errors.Is(err, service.ErrComponentDisabled):
		// FAILED_PRECONDITION 而不是 NOT_FOUND: 组件是存在的, 只是被有意关掉了.
		// Launcher 据此提示用户去设置里启用, 而不是说"找不到这个应用"
		return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_COMPONENT_DISABLED
	case errors.Is(err, service.ErrComponentFailed):
		return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_COMPONENT_FAILED
	default:
		return ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			ipcv1.LaunchComponentReason_LAUNCH_COMPONENT_REASON_SPAWN_FAILED
	}
}

// launchFailure 构造一个带 typed error_detail 的失败结果.
func launchFailure(reqID uint64, code ipcv1.StatusCode, reason ipcv1.LaunchComponentReason) *ipcv1.Envelope {
	failure := &ipcv1.Failure{Code: code}
	// error_detail 编码失败不该让整条响应发不出去: 外层 code 已经承载了
	// 调用方做决定所需的最低信息, detail 只是让它能更精确地展示
	if detail, err := proto.Marshal(&ipcv1.LaunchComponentErrorDetail{Reason: reason}); err == nil {
		failure.ErrorDetail = detail
	}
	return &ipcv1.Envelope{
		Body: &ipcv1.Envelope_LaunchComponentResult{
			LaunchComponentResult: &ipcv1.LaunchComponentResult{
				RequestId: reqID,
				Outcome:   &ipcv1.LaunchComponentResult_Failure{Failure: failure},
			},
		},
	}
}
