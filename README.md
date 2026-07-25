# nervud

Core Of Nervus OS

Nervus OS（NSOS）的内核守护进程。单进程 Go，systemd 管它的生命周期。

## 运行

生产镜像固定路径，无需参数：

```sh
/usr/libexec/nervus/nervud
```

开发机用两个 `-dev-*` 开关（生产二进制不该依赖它们）：

```sh
nervud -dev-skip-preflight -dev-allow-sched-degrade -log-level debug
```

| 开关 | 用途 |
|---|---|
| `-dev-skip-preflight` | 跳过只读镜像区自检。开发机没有 `/usr/libexec/nervus` 等路径 |
| `-dev-allow-sched-degrade` | 缺 `CAP_SYS_NICE` 时允许实时优先级降级。生产环境缺它直接退出 |

**必须以 systemd unit 运行**，不能直接跑二进制：组件的瞬态 unit 带
`BindsTo=nervud.service`（owner-death：nervud 死了组件跟着停）。裸跑时那个 unit
不存在，`StartTransientUnit` 会以 `Unit nervud.service not found` 失败，
组件永远起不来。开发机用 `systemd-run --unit=nervud --collect ...`。

## 依赖同步

```sh
scripts/sync-ipc.sh [commit|tag]
```

`nervus-ipc` 是协议真源。**它与 `nervus-system-server` 必须指向同一个 commit**，
否则内核与服务对同一份 Envelope 的理解会悄悄分叉——而两边都能编译、都能跑，
只在某个字段的行为上不一致。

## 测试

内核是 `//go:build linux`，**Windows 上跑不了测试**（`authority/ops.go`、
`scheduler/sched.go` 是 linux-only，不参与编译会连带 9 个包 build failed）。

```sh
go build ./... && go vet ./... && go test ./... && go test ./... -race
```

## 已知缺口

按严重度排。每一条都在代码里有对应注释，grep 括号里的标记能找到位置。

### 1. 权限执法整体短路（`V1GrantAll`）

`permission.V1GrantAll = true` 让安装时「申请即授予」、运行期跳过用户确认。
恢复执法要改回 `false` 并补齐 `DefaultCatalog`——权限 ID 的正式命名空间与取值表
尚未冻结。

连带影响：`ipc/lease.go` 直接采信客户端自报的 `controller_class`，
与 `control/class.go` 的「不能接受客户端自报值」暂时不一致。
`grep CONTROL_CLASS_SELF_REPORTED` 找全部位置。

### 2. Safety 停机信号发不出去

`safety.NopPath{}.SendHalt()` 直接 `return nil`，`NopReports{}.Reports()` 返回
nil channel。判定、锁存、epoch 递增、Supervisor 三级超时全都在跑，
但**「停机」这个动作发不出去，「停稳了」这个事实也收不回来**。

`safety.proto` 的五条消息已冻结，缺的是承载方式的决定：走专用高优先级通道
还是 Dispatch（该文件注释里标着「留待冻结」）。

### 3. 三张硬编码常量表

| 表 | 位置 |
|---|---|
| 接口→权限 | `endpoint.DefaultInterfaceCatalog()` |
| 权限定义 | `permission.DefaultCatalog()` |
| Resource | `resource.DefaultRegistry()` |

`provider_descriptor.proto` 是替换它们的解药（从签名 Descriptor 数据驱动注册），
但内核侧尚未接线。接线之前，加一款硬件仍然要改内核。

### 4. operation 没有调用方

`operation.Manager` 完整实现且有测试，但**零调用方**：Operation 查询在
envelope.proto 里标着 `[v2+]`，dispatch 也不创建 operation。
`LeaseValidator` 因此仍传 nil，运动类 operation 一律 fail-closed 拒绝。

### 5. 内建 endpoint 传不出 typed error_detail

`endpoint.BuiltinHandler` 的签名是 `(payload, StatusCode)`，没地方放
typed detail。`safety/builtin.go` 已经算出了 `WRONG_STATE`（别试了）与
`STOP_NOT_SETTLED`（等一会儿）的区分，但传不到调用方。
`grep TODO(builtin-detail)`。

### 6. 审计没有防篡改

`audit` 仍是往 slog 写。`internal/audit/audit.go` 的 TODO 写着要换
append-only 文件 + 轮转 + 完整性保护。

### 7. 其它接缝

- `health.New(safetyMod, ctl, nil)` —— 第三个观察者是 nil，因为
  `*service.Manager` 没实现 `Instances()`。补个方法就能接上
- `identity.Registry` 裸 New，没有 Module 外壳，与其它 10 个模块不一致
- `endpoint/route.go` 的 `req.Drain` 未接线，`drain=true` 退化成立即撤
