//go:build linux

package scheduler

import "golang.org/x/sys/unix"

// SCHED_OTHER 在内核里就是数值 0；x/sys/unix 没有为它单独命名常量，这里显式给出
const schedOther = 0

// setSched 对当前 OS 线程设置调度策略与优先级
//
// 用的是 sched_setattr(2)（x/sys/unix.SchedSetAttr），它是 sched_setscheduler 的
// 现代超集，用一个 SchedAttr 结构统一表达策略 + 优先级
//
// 注意事项
//
//		pid = 0 表示 当前线程，也就是调用方的 OS 线程
//		必须在已 runtime.LockOSThread 的情况 才能 传递 pid = 0
//	  否则 当前线程 不确定，且设完可能被 Go 运行时挪走
//		SCHED_FIFO / SCHED_RR 的实时优先级放在 SchedAttr.Priority（合法范围 1..99）
//		SCHED_OTHER 的 Priority=0 不需要实时优先级
//		设置实时策略需要 CAP_SYS_NICE Capability
//		无权限时将原样返回给调用方 EPERM
func setSched(policy Policy, priority int) error {
	var attr unix.SchedAttr
	switch policy {
	case PolicyFIFO:
		attr.Policy = unix.SCHED_FIFO
		attr.Priority = uint32(priority)
	case PolicyRR:
		attr.Policy = unix.SCHED_RR
		attr.Priority = uint32(priority)
	default:
		attr.Policy = schedOther
		attr.Priority = 0 // SCHED_OTHER 的静态优先级必须为 0
	}
	// flags = 0：作用于当前线程，不带 RESET_ON_FORK 等修饰
	return unix.SchedSetAttr(0, &attr, 0)
}
