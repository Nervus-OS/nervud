// 本文件把 operation 的 LeaseValidator 实现在 ipc 这一侧。
//
// # 为什么实现在这里，而不是在 operation 或 control 里
//
// 校验一次运动类 operation 的租约要同时拿到三样东西：
//
//	wire 句柄 → control.ID 的映射    住在 ipc 的 conn 里（连接作用域）
//	control 模块                      装配期注入 ipc
//	「这个租约覆盖哪个资源」          control.CheckLease 回答
//
// 只有 ipc 三样都有。operation 不该认识 control（依赖方向），control 也不该
// 认识连接作用域的 wire 句柄（那是传输层的概念）。所以这个适配器落在 ipc，
// 由 main.go 在装配期注入 operation.Manager。
//
// # 它拦的是什么
//
// 「拿着左臂的租约去动右臂」。lease_id 与 resource 都是合法的，各自都通得过
// 单独的校验——只有把两者放在一起看才发现对不上。而这类错误在现场的表现是
// 「另一条手臂动了」，没有任何日志会说是租约用错了。
package ipc

import (
	"github.com/nervus-os/nervud/internal/operation"
)

// OperationLeases 实现 operation.LeaseValidator。
//
// 它是 *Server 的一个视图而不是独立类型：需要的状态全在 Server 上，
// 再包一层只会多一个要保持同步的东西。
type OperationLeases struct {
	s *Server
}

// OperationLeaseValidator 返回可注入 operation.Manager 的校验器。
//
// s 为 nil 时返回的校验器恒 false——fail closed。装配顺序出错时，
// 运动类 operation 会被全部拒绝，而不是全部放行。
func (s *Server) OperationLeaseValidator() *OperationLeases {
	return &OperationLeases{s: s}
}

// ValidLease 复核一次运动类 operation 的租约绑定。
//
// 【任何一步存疑一律 false】。这条路径的下游是「机械臂开始按轨迹运动」，
// 而它的输入里有一个连接作用域句柄和一个调用方给的 epoch——两者都可能因为
// 时序而过期。宁可拒绝一次合法的创建，也不能放行一次基于失效授权的运动。
func (l *OperationLeases) ValidLease(
	owner operation.ConnHandle, leaseID, epoch uint64, resource string,
) bool {
	if l == nil || l.s == nil || l.s.leases == nil {
		return false
	}
	if leaseID == 0 || resource == "" {
		return false
	}

	// owner 必须是本 Server 上的连接。跨 Server 的句柄没有意义，而一个类型断言
	// 失败在这里意味着装配把别的东西接了进来——那时放行等于用一个来路不明的
	// 句柄去授权运动。
	co, ok := owner.(*conn)
	if !ok || co == nil || co.s != l.s {
		return false
	}

	id, ok := co.lookupLease(leaseID)
	if !ok {
		// 不是本连接持有的句柄。可能是伪造的，也可能是已经释放过的——
		// 两种情况的处置相同。
		return false
	}

	proof, err := l.s.leases.CheckLease(id, co.leaseConnID())
	if err != nil {
		// 租约已过期、已被抢占、或 Safety 已停机。CheckLease 内部把这些
		// 统一成错误，本层不需要区分：都不该放行。
		return false
	}

	// 【资源必须对得上】。句柄有效但指向别的资源，就是「拿着左臂的租约去动
	// 右臂」——两个字段各自都合法，只有放在一起看才发现问题。
	if proof.Resource != resource {
		return false
	}

	// 【epoch 必须一致，不是「不小于」】。调用方给的 epoch 来自它 Acquire 时
	// 拿到的那一个；现在的 epoch 更大意味着中途发生过 Safety 接管或抢占，
	// 那次授权已经作废。放行会让一次基于旧授权的运动开始执行。
	return proof.Epoch == epoch
}
