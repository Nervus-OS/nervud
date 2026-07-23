package safety

import (
	"errors"
	"time"
)

// Contract 是一个执行器 Resource 的 Safety Contract（NRCP §14.4）。它是 OEM 在
// Provider manifest 的 `safety_contract` 中声明、并由 nervud Policy 独立校验后确定的
// 时间预算与升级窗口。
//
// [REWRITE-v1] 本轮只定义类型 + 校验；manifest 解析留到 service/Provider 落地
// （见计划 Q2）。平台不规定统一停稳毫秒数：真实数值来自机器人风险分析、制动能力和
// 真机测试。nervud 可按风险收紧 OEM 声明，但不得被 OEM 降到系统安全地板以下。
type Contract struct {
	// HaltDispatchBudget 从原子锁存到提交高优先级停机信号的目标预算。
	// 超时只记录内核 Safety fault，Latch 保持。
	HaltDispatchBudget time.Duration

	// ProviderAcceptTimeout Provider 确认已接受停机请求（HaltAccepted）的期限。
	// 超时 → Provider/Resource 标 FAULT、停普通 Dispatch、转独立 MCU/watchdog/切电。
	ProviderAcceptTimeout time.Duration

	// DeviceStopAckTimeout MCU/控制器确认收到停机或输出已关闭（OUTPUT_DISABLED）的期限。
	// 超时 → 停运动心跳、等独立 watchdog；有硬切断则按 Policy 升级。
	DeviceStopAckTimeout time.Duration

	// StandstillTimeout 取得可信物理停稳证据的期限。
	// 超时 → Latch 保持、报 STANDSTILL_TIMEOUT、按设备策略继续切电/报警/人工处置。
	StandstillTimeout time.Duration

	// MCUWatchdogTimeout Host/Provider 失效后 MCU 本地停止的最大链路失联窗口。
	// 必须独立于 Linux/Provider，且小于该设备风险分析允许的最大失控窗口。
	MCUWatchdogTimeout time.Duration

	// StandstillConfirmationSupported 本设备是否具备可信停稳证据能力（编码器/速度估计）。
	// 为 false 时停止进度封顶在 OUTPUT_DISABLED（NRCP §14.1）。
	StandstillConfirmationSupported bool
}

// DefaultContract 返回一组保守的 fail-closed 占位默认值。真机必须按测量结果覆盖。
//
// ProviderAcceptTimeout 取 100ms 与 NRCP §7.2 示例的 requested_ack_deadline_ms 对齐；
// MCUWatchdogTimeout 的 300ms 只是 [ADVX-LEGACY] 原型参数，不是平台默认或安全认证保证。
func DefaultContract() Contract {
	return Contract{
		HaltDispatchBudget:              5 * time.Millisecond,
		ProviderAcceptTimeout:           100 * time.Millisecond,
		DeviceStopAckTimeout:            200 * time.Millisecond,
		StandstillTimeout:               1 * time.Second,
		MCUWatchdogTimeout:              300 * time.Millisecond,
		StandstillConfirmationSupported: false,
	}
}

// Validate 做结构性校验：全部预算为正，且升级窗口单调
// （accept ≤ deviceAck ≤ standstill）。
//
// 「不得低于 Resource 安全地板」的比较需要 Resource 风险模型，留到 resource 落地时
// 由 Policy 用 ValidateAgainstFloor 之类完成；本轮只保证 Contract 自身自洽。
func (c Contract) Validate() error {
	if c.HaltDispatchBudget <= 0 || c.ProviderAcceptTimeout <= 0 || c.DeviceStopAckTimeout <= 0 ||
		c.StandstillTimeout <= 0 || c.MCUWatchdogTimeout <= 0 {
		return errors.New("safety: all contract budgets must be positive")
	}
	if c.ProviderAcceptTimeout > c.DeviceStopAckTimeout {
		return errors.New("safety: provider_accept_timeout must not exceed device_stop_ack_timeout")
	}
	if c.DeviceStopAckTimeout > c.StandstillTimeout {
		return errors.New("safety: device_stop_ack_timeout must not exceed standstill_timeout")
	}
	return nil
}
