package authority

import "errors"

var (
	// ErrPolicyDenied 策略裁决拒绝
	//
	// Authority 路径上没有 Policy 步骤（调用者同属 TCB，见 authority.go的 do 说明）
	// 本错误暂无产生点；保留它是给 do 里标注的 Policy 接缝用的
	// internal/permission 拒绝 App 请求时也应复用同一语义
	ErrPolicyDenied = errors.New("authority: policy denied")

	// ErrInvariantViolated 底层不变量被违反
	// 这类错错误不可能被任何策略豁免 - 策略说 yes 也照样拒
	ErrInvariantViolated = errors.New("authority: invariant violated")

	// ErrUnsupportedPlatform 该特权操作只在 Linux 上有实现
	//
	// 与 scheduler 的 allowDegrade 不同，这里不提供降级开关：调度优先级设不上
	// 只是实时性退化，而特权操作静默 no-op 会让上层误以为目录已建好、进程已停掉
	// 属于危险的假成功。开发机（Windows/macOS）上碰到本错误应视为装配错误
	ErrUnsupportedPlatform = errors.New("authority: operation requires linux")
)
