package safety

// ReportKind 区分 OEM Provider 在 Safety 边界回传的事实类型。
type ReportKind uint8

const (
	// ReportHaltAccepted Provider 接受了停机要求（ != 已物理停稳）。
	ReportHaltAccepted ReportKind = iota + 1
	// ReportStopProgress 停止进度推进到某个相位。
	ReportStopProgress
	// ReportStandstillConfirmed 取得可信停稳证据。
	ReportStandstillConfirmed
	// ReportProviderFault Provider 故障。
	ReportProviderFault
)

// FaultCode 是 Provider 故障的分类。数值须与 safety.proto 的 FaultCode 一致。
type FaultCode uint32

const (
	FaultUnspecified FaultCode = 0
	FaultDeviceError FaultCode = 1
	FaultLinkLost    FaultCode = 2
)

// ProviderReport 是 Provider -> nervud 的边界事实（镜像 safety.proto 的 HaltAccepted /
// StopProgress / StandstillConfirmed / ProviderFault）。它无指针、可按值传递，
// 由 Supervisor 用来推进 StopProgress 状态机。
//
// Epoch 必须匹配当前锁存世代：陈旧 epoch 的上报一律忽略。
type ProviderReport struct {
	Kind  ReportKind
	Epoch uint64
	Phase StopPhase // ReportStopProgress 时有效
	Fault FaultCode // ReportProviderFault 时有效
}

// StopProgressSource 是 Supervisor 消费 Provider 上报的接缝。返回一个有界只读 channel；
// 实际由 ServiceHost/Dispatch 把 Provider 的 safety.proto 消息喂进来（本轮不接线）。
type StopProgressSource interface {
	Reports() <-chan ProviderReport
}

// NopReports 是 v1 无真实 Provider 时的 stub：返回 nil channel，
// Supervisor 的 select 分支永不触发（即没有任何上报）。
func NopReports() StopProgressSource { return nopReports{} }

type nopReports struct{}

func (nopReports) Reports() <-chan ProviderReport { return nil }
