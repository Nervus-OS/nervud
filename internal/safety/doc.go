// Package safety 是 Safety Gate：原子锁存、motion epoch 递增、撤销 actuator lease
// StopProgress 跟踪、升级与 re-arm。顶层状态 NORMAL/SAFETY_LATCHED/OEM_RECOVERY/REARM_REQUIRED
//
// Stop Lane 热路径要求预热后零堆分配：禁止 new、会扩容的 append、闭包任务
// 禁止日志格式化 / Protobuf 编码 / 普通 RPC 队列进入。只投递启动时预构造的固定停止信号
package safety
