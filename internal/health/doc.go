// Package health 聚合内核自身与其监督的 App/Service 组件的健康状态。
//
// health 只表示 nervud 内核进程及其监督组件当前是否正常运行。
// 它与 Runtime Availability（Resource/Provider/设备的
// available/degraded/fault/offline）是两条正交的轴，后者的权威留在
// internal/resource（v2+），本包不重新捡起来做，也不把两者混成一个概念。
//
// health 不是第二个真相源：它只读 safety/control/service 三个已有权威源
// 各自导出的只读快照方法，现读现算，调用之间不留状态，也不新增任何定时器、
// goroutine 或轮询。v1 不新增 wire 协议，也不做主动探测，避免 health
// 聚合器反过来成为新的状态源或生命周期负担。
package health
