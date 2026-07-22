// Package scheduler 提供 Safety/Control 优先级执行 Lane
//
// 背景（架构文档 sec 6）：
//
//	Go 的 goroutine 没有公开的优先级概念，Go 运行时会把 goroutine 在多个
//	OS 线程之间自由搬运。要让「急停」这类路径获得 Linux 实时调度优先级
//	唯一可行的办法是：
//	  1. runtime.LockOSThread()  把当前 goroutine 钉死在一个专属 OS 线程上
//	     Go 调度器从此不再把别的 goroutine 塞进这个线程，也不把它搬走
//	  2. sched_setattr(2)        对这个 OS 线程设置真实的 Linux 实时调度策略
//	     （SCHED_FIFO / SCHED_RR）和优先级（1..99）
//
// 优先级分配：Emergency Stop 99 / Safety Supervisor 97-98 / Control 40
//
// 文件布局：跨平台通用部分（类型、常量、Lane 装配）在 scheduler.go 与 spawn.go
// 真正调用 syscall 的部分在 sched.go，带 //go:build linux。本包不提供非 Linux
// 实现——非 Linux 平台上整个包编译不过，这是刻意的：一个静默 no-op 的实现会让
// 「Safety Lane 有实时优先级」变成假信心
//
// 依赖边界：按 sec 4，除 authority 外，只有本包允许直接 import syscall /
// golang.org/x/sys/unix
package scheduler
