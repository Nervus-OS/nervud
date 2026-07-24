// Package health 聚合内核自身与其监督的 App/Service 组件的健康状态。
//
// 这是 nervud-内核与系统服务架构决策.md §3「核心和服务健康状态」意义上的
// health：nervud 这个内核进程自己、以及它监督的组件，现在活得好不好。
// 它与 NRCP §5.3 Runtime Availability（Resource/Provider/设备的
// available/degraded/fault/offline）是两条正交的轴，后者的权威留在
// internal/resource（v2+），本包不重新捡起来做，也不把两者混成一个概念。
//
// health 不是第二个真相源：它只读 safety/control/service 三个已有权威源
// 各自导出的只读快照方法，现读现算，调用之间不留状态，也不新增任何定时器、
// goroutine 或轮询。v1 不新增任何 wire 协议、不做主动探测。见
// Health模块设计方案.md。
package health
