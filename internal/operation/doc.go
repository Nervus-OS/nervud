// Package operation 是 nervud 拥有的 Operation Manager：给"要花时间、需要取消/
// 进度/终态确认"的系统协调长任务（机械臂轨迹、回零、移到位姿、导航到点）一个
// 由内核持有的状态机与句柄。
//
// # 范围（v1 最小面）
//
// 本包实现 v1 最小可用面：内存态状态机 + 对外操作面（Create/Get/
// Cancel/Subscribe）+ Provider 回报接缝（ProviderReporter）+ 无阻塞的 Safety
// 接管（SafetySupersede）。不做 v2 的跨重启持久化、复杂多资源原子 operation，
// 也不做 operation_type Registry 归一化。重启 = 新 host session，旧 operation
// 一律丢弃、不恢复（与 motion epoch 语义一致， 留 v2）。
//
// # 四条铁律
//
//  1. nervud 拥有 operation：operation_id、状态机、caller、resource set、
//     deadline、取消、终态、审计全归本包。Provider 不签发 id、不改 origin type、
//     系统取消后不得继续控制资源。
//  2. 终态只写一次：SUCCEEDED/FAILED/CANCELLED 写入后不可再变（canTransition
//     对终态无出边 + 单锁下的 compare-and-set）。PENDING/RUNNING/
//     CANCEL_REQUESTED 不得携带 terminal outcome。
//  3. 所有枚举 *_UNSPECIFIED=0 作非法缺省，未知值 fail-closed。
//  4. 绝不阻塞 Safety：SafetySupersede 只做一次原子写 + 一次非阻塞投递即返回，
//     真正的状态收敛与订阅 fan-out 在本包自己的后台 goroutine 里做。
//
// # 可拓展（数据驱动，不写死）
//
// 哪个方法产生 operation 由 Method Registry（A3）的 method 元数据决定
// （returns_operation + 是否需要 lease），不是本包里写一张方法名清单。是否为
// 运动类（需 lease 校验）由 Create 的 leaseID 参数驱动：leaseID != 0 即运动类。
// 自检：加一个新的 operation-returning OEM 方法，不需要改本包任何 Go 代码。
//
// # 依赖方向
//
// 本包只 import identity（Caller 类型）、audit（Recorder/Event）、ipcv1
// （StatusCode）。对 resource/control 的依赖走消费者定义的窄接口
// （ResourceValidator/LeaseValidator），由 main.go 在装配阶段注入具体实现，
// 因此本包可独立构建和单测，不阻塞在 dispatch wire 接线未落地上。
//
// # wire proto
//
// operation 的 IPC 面（CreateOperation/GetOperation/CancelOperation/
// OperationEvent）需要 nervus-ipc 的 operation proto，目前不存在。本包先用本地
// Go 类型把状态机 + 接缝 + 测试做完；本地类型 <-> ipcv1.*Operation* 的薄适配层
// 位置标 TODO(A-operation-proto)，等 A 组冻结 proto 后由 dispatch(B1) 接线补。
package operation
