package safety

import "github.com/nervus-os/nervud/internal/motiongate"

// Snapshot 是安全态的一致只读快照，供 ①面向开发者的观察面使用。
type Snapshot struct {
	State     motiongate.State
	Epoch     uint64
	StopPhase StopPhase
}

// Observer 让上层（未来的 IPC 事件、UI）读取安全态。v1 只提供快照读取；
// 推送订阅（EndpointDied 那样的事件流）在 IPC dispatch 落地后接。
//
// *Module 实现本接口。
type Observer interface {
	SafetySnapshot() Snapshot
}

// Controller 让受权限的调用方请求软件急停。权限由 nervud 在 IPC 层裁决——本接口
// 只表达「存在一个可请求急停的能力」，不代表任何人都能调（HUMAN/UI 才可，且需授权）。
//
// *Module 实现本接口（RequestStop 即 Trip）。
type Controller interface {
	RequestStop(reason ReasonCode)
}
