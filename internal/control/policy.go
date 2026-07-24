// 本文件是租约的时间预算。HUMAN 与 AI 分成两组取值，因为它们的失效模式根本不同：
// 人会松手、会断网、会走开；Agent 不会松手，但会被模型或网络卡住
package control

import (
	"fmt"
	"time"
)

// ClassPolicy 是某一类控制主体的租约预算
type ClassPolicy struct {
	// TTL 是签发与每次续租给出的有效期上限。申请方可以要一个更短的值，不能要更长的
	TTL time.Duration

	// Deadman 是命令新鲜度窗口上限。同样只能要更短、不能要更长 - 更长 = 更弱
	//
	// 为 0 且 RequireDeadman 为 false 时，本类别默认不要求 deadman
	Deadman time.Duration

	// RequireDeadman 为 true 时，本类别的租约必须带 deadman，申请方不能要求 0
	RequireDeadman bool
}

// Policy 是本模块的全部时间预算
type Policy struct {
	Human ClassPolicy
	AI    ClassPolicy
}

// DefaultPolicy 返回一组保守的 fail-closed 占位默认值
//
// HUMAN：TTL 2s + deadman 300ms + 强制要求 deadman。手机遥控靠输入与心跳续租，
// 人一松手或网络断开就必须在几百毫秒内失去控制权并回到 NONE。
//
// AI：TTL 1s，不要求 deadman。Agent 是本地进程，不会松手，所以 deadman 意义不大；
// 但它会被模型推理、云端请求或死锁卡住，因此用更短的 TTL 逼它显式续租来证明自己还活着。
//
// 与 safety.DefaultContract 同一处理方式：这些数值是保守占位，不是平台承诺。
// 真机必须按遥控链路实测（往返延迟、抖动、丢包）覆盖
func DefaultPolicy() Policy {
	return Policy{
		Human: ClassPolicy{TTL: 2 * time.Second, Deadman: 300 * time.Millisecond, RequireDeadman: true},
		AI:    ClassPolicy{TTL: 1 * time.Second},
	}
}

// Validate 做结构性校验：TTL 必须为正；要求 deadman 的类别必须给出正的 deadman；
// deadman 不得长于 TTL（否则 TTL 先到期，deadman 永远不会触发，等于没配）
func (p Policy) Validate() error {
	if err := p.Human.validate("human"); err != nil {
		return err
	}
	return p.AI.validate("ai")
}

func (c ClassPolicy) validate(name string) error {
	if c.TTL <= 0 {
		return fmt.Errorf("control: %s ttl must be positive", name)
	}
	if c.Deadman < 0 {
		return fmt.Errorf("control: %s deadman must not be negative", name)
	}
	if c.RequireDeadman && c.Deadman <= 0 {
		return fmt.Errorf("control: %s requires deadman but none is configured", name)
	}
	if c.Deadman > c.TTL {
		return fmt.Errorf("control: %s deadman must not exceed ttl", name)
	}
	return nil
}

// forClass 取某一类别的预算。Class 已在 Request 校验阶段确认合法，因此这里只有两支
func (p Policy) forClass(c Class) ClassPolicy {
	if c == ClassHuman {
		return p.Human
	}
	return p.AI
}

// resolve 把申请方给出的 TTL/deadman 与 Policy 上限合成为最终取值
//
// 语义固定：0 = 沿用 Policy 默认；非 0 = 申请方自选，但只能更严（更短），超限即拒绝。
// 只能更严这条让 SDK 可以在弱网下主动缩短窗口，而系统安全地板不会被调松
func (c ClassPolicy) resolve(ttl, deadman time.Duration) (time.Duration, time.Duration, error) {
	if ttl < 0 || deadman < 0 {
		return 0, 0, fmt.Errorf("%w: negative duration", ErrInvalidRequest)
	}
	if ttl == 0 {
		ttl = c.TTL
	}
	if ttl > c.TTL {
		return 0, 0, fmt.Errorf("%w: ttl %s exceeds limit %s", ErrPolicyViolation, ttl, c.TTL)
	}

	if deadman == 0 {
		deadman = c.Deadman
	}
	if c.Deadman > 0 && deadman > c.Deadman {
		return 0, 0, fmt.Errorf("%w: deadman %s exceeds limit %s", ErrPolicyViolation, deadman, c.Deadman)
	}
	if c.RequireDeadman && deadman <= 0 {
		return 0, 0, fmt.Errorf("%w: this controller class requires a deadman", ErrPolicyViolation)
	}
	if deadman > ttl {
		return 0, 0, fmt.Errorf("%w: deadman %s exceeds ttl %s", ErrPolicyViolation, deadman, ttl)
	}
	return ttl, deadman, nil
}
