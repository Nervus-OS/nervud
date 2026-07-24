// 本文件定义控制主体类别（Class）、有效控制来源（Source）与唯一合法的抢占矩阵
package control

// Class 是持有 ControlLease 的控制主体类别（ 的 controller_class）
//
// 只有 HUMAN 与 AI 两种。NONE 不是 Class，它表示当前没有任何有效租约，实现上
// 就是 nil lease，因此客户端不能申请它。SAFETY 也不是 Class，它是独立的
// Gate/latch，不能与 HUMAN/AI 共用同一种 lease 实现
//
// Class 必须由可信调用方根据身份与权限裁决后传入，不能接受客户端自报值
type Class uint8

const (
	// ClassUnspecified 是零值哨兵，永远不是合法申请
	//
	// 与 identity.TrustProfile、safety.ReasonCode 对 0 的处理同一个理由：漏填必须
	// fail closed，不能因为调用方没赋值就默默拿到某个真实类别
	ClassUnspecified Class = 0

	// ClassHuman 表示人正在通过摇杆、按键或实时遥控闭合控制环
	ClassHuman Class = 1

	// ClassAI Agent 在自主观察、规划并执行。判定标准是谁在闭合执行控制环，
	// 不是命令最初来自哪个界面 - 用户在手机上说去厨房看看之后由 Agent 自主
	// 执行的那一段，是 AI 而不是 HUMAN
	ClassAI Class = 2
)

// Valid 报告 c 是否为一个已定义的类别
func (c Class) Valid() bool { return c == ClassHuman || c == ClassAI }

func (c Class) String() string {
	switch c {
	case ClassHuman:
		return "HUMAN"
	case ClassAI:
		return "AI"
	default:
		return "UNSPECIFIED"
	}
}

// Source 是当前谁在闭合执行器控制环的四值投影
//
// 与 Class 相反，本类型的零值是一个合法结论：SourceNone 表示当前没有有效租约，
// 那是系统刚启动、主动释放、超时、断线或 re-arm 之后的正常状态，不是漏填。
//
// 两者对 0 的处理刻意相反：Class 是申请方传进来的东西（漏填必须拒绝），Source 是
// 内核算出来的结论（NONE 是真结论）
type Source uint8

const (
	SourceNone   Source = 0
	SourceAI     Source = 1
	SourceHuman  Source = 2
	SourceSafety Source = 3
)

func (s Source) String() string {
	switch s {
	case SourceAI:
		return "AI"
	case SourceHuman:
		return "HUMAN"
	case SourceSafety:
		return "SAFETY"
	default:
		return "NONE"
	}
}

// canPreempt 报告 want 类别的申请者能否抢占 held 类别的在持租约
//
// 唯一合法的抢占是 HUMAN 抢占 AI（HUMAN 抢占 AI，或一个控制者原子
// 替换另一个控制者只递增一次 epoch）。其余一律不可抢：
//
//	AI 抢 HUMAN  永远不行 - 人正在遥控时被 AI 夺走控制权是不可接受的
//	同 class 相抢  v1 一律拒绝（fail closed）。两台手机同时要 HUMAN 时，
//	        后来者拿到可区分的 ErrHeldByHuman，由上层去请当前持有者让出 -
//	        让出的决定权在人，不在申请者。放开同级接管需要产品侧先拍板
//	        谁有资格让出，那属于 remote session/配对那一层
//
// 注意同一连接重复申请不走这里：那是幂等续租，不是抢占（见 Module.Acquire）
func canPreempt(want, held Class) bool {
	return want == ClassHuman && held == ClassAI
}
