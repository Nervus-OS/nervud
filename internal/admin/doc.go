// Package admin 是 nervud 的【特权管理控制面】：一条 root-only 的 UDS，让本机
// 运维工具（cmd/nervusctl）触发装包/卸载/停用启用/权限授撤，而不必成为 App。
//
// 为什么与 App 控制面（internal/ipc）分开：
//
//   - App 控制面（/run/nervus/nervud.sock，0666）只接受 UID 落在 App 段的连接，
//     root 会被 Invariants.CheckUID 直接拒绝——运维工具（以 root 运行）根本连不上。
//   - 管理操作是【特权】的（装包会把 staging 提交成系统里的可执行代码、改权限状态），
//     必须由「系统持有的确认通道」触发，而不是任何普通 App（架构红线 §6.1/§6.6：
//     授权权力只在 nervud；危险动作只能请求，确认框由系统持有）。因此单开一条
//     0600、SO_PEERCRED 校验为运维身份的通道，两套准入规则不混。
//
// 单写者纪律（B4 spec / 架构红线 §10）：Package Registry 的唯一权威真源永远是
// nervud 进程内的 pkgregistry.Module。nervusctl【不】直接改磁盘 Registry——它只
// 把命令经本通道投递给 nervud，由 nervud 的同一个 Module 执行。签名验证、Arbitrate、
// OEM 副署、ABI、权限 Intersect 全部发生在 pkgregistry 里，本包不做任何安全判定，
// 只做：身份准入 + 参数/路径逃逸校验 + 转调 + 结果投影。
//
// staging 归 nervud 掌控（见 CmdBeginStaging）：由 nervud 在自己的 staging 根下建
// 目录并把路径发回 CLI，CLI 解包进去后再触发 install。install 时校验该路径确实是
// staging 根的直接子目录（路径逃逸校验），再让 pkgregistry 复核并原子提交。
package admin
