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

`nervus-ipc` 是协议真源。nervud 直接依赖仓库根 module
`github.com/nervus-os/nervus-ipc`，不再混用旧的 `/go` 子模块。**nervud 与
`nervus-system-server` 必须指向同一个 IPC commit**，否则内核与服务对同一份
Envelope 的理解会悄悄分叉。

## 测试

内核是 `//go:build linux`，**Windows 上跑不了测试**（`authority/ops.go`、
`scheduler/sched.go` 是 linux-only，不参与编译会连带 9 个包 build failed）。

```sh
go build ./... && go vet ./... && go test ./... && go test ./... -race
```

## 通用能力模型

接口、method schema、权限和 Resource 统一进入一份不可变 Catalog。系统包与动态
Provider 的签名 `ProviderArtifacts` 经过校验后发布；Endpoint 解析、method gate、
权限裁决和 Resource 查询都读同一 revision。添加摄像头、麦克风或 OEM 私有能力时，
Provider 提交描述与 schema，不为每种能力增加一套内核 IPC 消息。

大数据不塞进控制面 Envelope。通用 Transfer manager 使用独立 Unix socket，控制面
只签发绑定 route、连接、权限、Resource 和过期时间的传输句柄。Catalog 删除定义或
改变 generation 时，旧 Dispatch、ControlLease 和 Transfer authority 会一起撤销。

## 已知缺口

### 1. Safety 停机信号发不出去

`safety.NopPath{}.SendHalt()` 直接 `return nil`，`NopReports{}.Reports()` 返回
nil channel。判定、锁存、epoch 递增、Supervisor 三级超时全都在跑，
但**「停机」这个动作发不出去，「停稳了」这个事实也收不回来**。

`safety.proto` 的五条消息已冻结，缺的是承载方式的决定：走专用高优先级通道
还是 Dispatch（该文件注释里标着「留待冻结」）。

### 2. Provider 收不到可信 ExecutionContext

IPC 文档要求运动类 Dispatch 附带 `lease_id/controller_class/motion_epoch/deadline`，
但当前 `Dispatch` schema 实际只有 `CallerContext`。nervud 可以在派发前验证租约并
在撤权时取消 route，却无法把可信 epoch 交给 Provider 做最后一道陈旧命令检查。
这个缺口必须先在 `nervus-ipc` 增加通用 `ExecutionContext` 字段，再由内核接线；
不能靠某个摄像头或运动 Provider 自定义 IPC 绕过。

### 3. 用户确认入口尚未闭合

`USER_CONSENT` 权限已经区分安装资格与运行期状态，默认拒绝，授撤会持久化并联动
路由、传输、控制租约和进程沙箱。但目前只有 root 管理通道能写运行期状态，尚无
系统持有的确认 UI/broker capability。

`controller_class` 当前策略允许调用方自报，AI 也可申请 `HUMAN`，并以
`ipc.AcquireControl.classSelfReported` 记审计。这是明确的临时策略，不是可信的人在场
证明；以后决定会话和用户控制权模型时，应在同一通用策略点收紧，不改 Provider IPC。

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
- 安装流程的 Catalog、Registry、Identity、Permission 发布有回滚与 fail-closed，
  但文件提交、记账和多份投影还不是一个可恢复的完整事务
