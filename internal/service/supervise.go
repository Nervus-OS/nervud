// Package service 本文件是组件实例的 supervisor 循环与崩溃分级处置.
//
// 每个运行中的实例由一个supervisor goroutine 独占监视: 起进程 -> 等退出 ->
// 判定 (预期停止 / 崩溃) -> 按 criticality 退避重启或熔断. 阻塞调用
//
//	(StartSandboxedProcess / WaitProcess) 一律不持 mu; 只有读写实例状态的
//
// 瞬间才短暂持 mu, 避免一个卡住的 systemd 调用锁住整个 Manager.
package service

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

const (
	restartBackoffMin = 1 * time.Second
	restartBackoffMax = 60 * time.Second
	// crashWindow / crashThreshold: 滑动窗口内崩溃达到阈值即熔断
	crashWindow    = 10 * time.Second
	crashThreshold = 5
	// startStopTimeout 给单次 StartSandboxedProcess/StopProcess 的上限 - 即便
	// systemd/D-Bus 卡住, 也不让一个 supervisor 无限期阻塞. 等一个长期运行组件
	// 退出 (WaitProcess) 则用 m.ctx, 不设此上限
	startStopTimeout = 30 * time.Second

	// nervudUnit 是 nervud 自身的 systemd unit 名. 组件瞬态 unit BindsTo 它,
	// 保证 nervud 被 SIGKILL 后组件也由 systemd 停止
	nervudUnit = "nervud.service"
	// registryDir 是 nervud 的可信状态目录, 含 _grants/_devmode/ledger/uid 分配器.
	// 组件沙箱把它设 InaccessiblePaths, 任何组件都读不到
	registryDir = "/var/lib/nervus/registry"
	// permStorageUser 是访问共享用户文档区 (Invariants.UserDataRoot) 所需的权限.
	// 与中央 catalog bootstrap 里的条目必须同名 - 那边是定义, 这边是执法点
	permStorageUser = "perm.storage.user"
	// permStorageShared 是访问服务间共享区 (Invariants.SharedRuntimeRoot /
	// SharedPersistRoot) 所需的权限. 与中央 catalog bootstrap 里的条目
	// 必须同名 - 那边是定义, 这边是执法点
	permStorageShared = "perm.storage.shared"

	// x11SocketDir 是 X11 显示服务器的 unix socket 目录.
	//
	// 路径写死是对的: 它由 X11 协议实现 (libxcb / libX11) 硬编码, 客户端不读
	// 任何配置就去连 /tmp/.X11-unix/X<display>. 这里换个位置只会让客户端找不到.
	x11SocketDir = "/tmp/.X11-unix"

	// defaultDisplay 是 DISPLAY 未在 nervud 环境里给出时的取值.
	// 机器人是单显示设备,:0 是唯一合理的缺省
	defaultDisplay = ":0"
)

// displayEnv 给图形组件准备 DISPLAY / XAUTHORITY.
//
// 取值透传自 nervud 自己的环境 (由 systemd unit 或镜像的 environment 文件给出),
// 而不是写死: 接了外接屏, 跑在 WSLg, 或用 Wayland 的 Xwayland 时 DISPLAY 都不同,
// 写死等于把部署形态钉进内核. DISPLAY 缺失时退回:0 - 一个能工作的缺省,
// 比让组件带着空 DISPLAY 启动再报一句难懂的错强.
//
// XAUTHORITY 只在 nervud 环境里确实有时才传: 传一个指向不存在文件的路径,
// X11 客户端会拒绝连接, 比不传更糟 (不传时会走 no-auth 或 XDG 缺省查找).
func displayEnv() []string {
	display := os.Getenv("DISPLAY")
	if display == "" {
		display = defaultDisplay
	}
	env := []string{"DISPLAY=" + display}
	if xauth := os.Getenv("XAUTHORITY"); xauth != "" {
		env = append(env, "XAUTHORITY="+xauth)
	}
	return env
}

// unitName 由 (pkg, comp) 生成 systemd 瞬态 unit 名. pkg/comp 的字符集都禁止 '-'
//
//	(manifest.validIDSegment), 因此 "nervus-<pkg>-<comp>.service" 对不同组件唯一,
//
// 不会碰撞
func unitName(pkg, comp string) string {
	return "nervus-" + pkg + "-" + comp + ".service"
}

// effectiveCriticality 计算生效的 criticality: Ordinary 包声明高于 optional 一律
// 降级, 否则第三方 App 可自称 vital, 并通过反复崩溃触发整机停机拒绝服务
func effectiveCriticality(e pkgregistry.Entry, c pkgregistry.Component) pkgregistry.Criticality {
	crit := c.Criticality
	if crit == "" {
		crit = pkgregistry.CriticalityOptional
	}
	if e.Trust == identity.TrustOrdinary && crit.Rank() > pkgregistry.CriticalityOptional.Rank() {
		return pkgregistry.CriticalityOptional
	}
	return crit
}

// startLocked 建实例并起 supervisor. 调用方必须持 m.mu
//
// 若该 key 已有一个终态实例 (StateStopped/StateFailed - on-demand 组件被停止后,
// 或崩溃熔断后, 都会停在 byKey 里而不是被摘除), 这里不panic, 而是当作全新
// 启动处理: 旧 supervisor goroutine 在把状态置为终态之前已经真正停掉了对应的
// systemd unit (stopProc/drain 发生在 setState 之前; 熔断则是重试耗尽, 进程已不
// 在跑), 所以外部一旦观察到终态, 旧实例就不会再被那个 goroutine 写入, 直接用新
// *Instance 覆盖 byKey/byUnit, 起新 supervisor 是安全的 - 这正是 EnsureStarted 对
// 一个此前跑过又停止/熔断的 on-demand 组件重新拉起时必须支持的路径 (见
// internal/endpoint 的 Resolve on-demand 拉起分支)
func (m *Manager) startLocked(e pkgregistry.Entry, c pkgregistry.Component) {
	if m.stopped {
		return
	}
	key := componentKey{e.Manifest.PackageID, c.ID}
	if inst, ok := m.byKey[key]; ok && (inst.State == StateRunning || inst.State == StateStarting) {
		return // 已在跑, 幂等
	}
	inst := &Instance{
		PackageID:   e.Manifest.PackageID,
		ComponentID: c.ID,
		UID:         e.UID,
		Generation:  e.RuntimeGeneration,
		Unit:        unitName(e.Manifest.PackageID, c.ID),
		Type:        c.Type,
		Runtime:     c.Runtime,
		Crit:        effectiveCriticality(e, c),
		LaunchMode:  c.LaunchMode,
		State:       StateStarting,
		stopCh:      make(chan struct{}),
		done:        make(chan struct{}),
	}
	m.byKey[key] = inst
	m.byUnit[inst.Unit] = inst
	m.wg.Add(1)
	go m.supervise(inst, e, c)
}

// requestStop 通知实例的 supervisor: 这是预期内停止, 退出后不要重启 (幂等)
func (m *Manager) requestStop(inst *Instance) {
	inst.stopOnce.Do(func() { close(inst.stopCh) })
}

// supervise 是单个实例的监视循环
func (m *Manager) supervise(inst *Instance, e pkgregistry.Entry, c pkgregistry.Component) {
	// done 在最后关闭: 此刻 unit 已停, 状态已定, ReloadPackage 可安全起新版本
	defer func() {
		close(inst.done)
		m.wg.Done()
	}()

	backoff := m.backoffMin
	for {
		req, err := m.buildStartReq(e, c, inst.Unit)
		if err != nil {
			// 构造请求就失败 (如路径不合法): 重试也不会好, 直接熔断
			m.audit(inst, "service.start", true, err)
			m.setState(inst, StateFailed)
			return
		}

		m.setState(inst, StateStarting)
		startCtx, cancelStart := context.WithTimeout(m.ctx, startStopTimeout)
		h, serr := m.auth.StartSandboxedProcess(startCtx, authority.SubjectKernel(), req)
		cancelStart()
		if serr != nil {
			if m.ctx.Err() != nil { // 正在关停
				m.setState(inst, StateStopped)
				return
			}
			m.audit(inst, "service.start", true, serr)
			if !m.recordCrashAndContinue(inst) {
				m.onCircuitBreak(inst)
				return
			}
			if !m.backoffWait(&backoff, inst) {
				return
			}
			continue
		}

		m.onStarted(inst, h)
		backoff = m.backoffMin

		// 起一个 goroutine 阻塞等退出; 主循环 select 退出/停止/关停
		exitCh := make(chan error, 1)
		go func(handle authority.ProcessHandle) {
			_, werr := m.auth.WaitProcess(m.ctx, handle)
			exitCh <- werr
		}(h)

		select {
		case <-inst.stopCh:
			// 预期停止. 关键由 supervisor 自己 StopProcess, 不依赖外部调用方 -
			// StopComponent/Stop 可能在本组件还处于 Starting, Handle 尚未落定时就快照
			// 到空 Handle 而没真正停掉它 (修复). 此刻 supervisor 手里的 h 一定有效
			m.stopProc(h)
			m.drain(exitCh)
			m.setState(inst, StateStopped)
			return
		case <-m.ctx.Done():
			// 整体关停: 同样由 supervisor 兜底停自己的 unit, 避免 Starting 窗口漏停
			m.stopProc(h)
			m.drain(exitCh)
			m.setState(inst, StateStopped)
			return
		case werr := <-exitCh:
			// 自然退出. 先复核是否其实是预期停止/关停竞态
			select {
			case <-inst.stopCh:
				m.setState(inst, StateStopped)
				return
			default:
			}
			if m.ctx.Err() != nil {
				m.setState(inst, StateStopped)
				return
			}
			// 崩溃 (service 不该自己退出)
			m.audit(inst, "service.crash", true, werr)
			if !m.recordCrashAndContinue(inst) {
				m.onCircuitBreak(inst)
				return
			}
			if !m.backoffWait(&backoff, inst) {
				return
			}
		}
	}
}

// stopProc 停掉一个句柄对应的 systemd unit. 用独立的有界 ctx 而非 m.ctx -
// 关停路径上 m.ctx 已被 cancel, 用它 StopProcess 会立刻 ctx 失败, unit 停不掉.
// StopUnit 幂等, 与外部 StopComponent/Stop 的调用重叠也无害
func (m *Manager) stopProc(h authority.ProcessHandle) {
	if h.Unit() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), startStopTimeout)
	defer cancel()
	if err := m.auth.StopProcess(ctx, authority.SubjectKernel(), authority.StopProcessRequest{Handle: h}); err != nil {
		m.log.Warn("service: supervisor StopProcess failed", "unit", h.Unit(), "err", err)
	}
}

// drain 等 exitCh 或关停信号, 避免 WaitProcess goroutine 泄漏也不永久阻塞
func (m *Manager) drain(exitCh <-chan error) {
	select {
	case <-exitCh:
	case <-m.ctx.Done():
	}
}

// onStarted 在进程起成功后更新句柄与状态并审计
func (m *Manager) onStarted(inst *Instance, h authority.ProcessHandle) {
	m.mu.Lock()
	inst.Handle = h
	inst.State = StateRunning
	m.mu.Unlock()
	m.audit(inst, "service.started", false, nil)
}

// setState 在持 mu 时更新实例状态
func (m *Manager) setState(inst *Instance, s State) {
	m.mu.Lock()
	inst.State = s
	m.mu.Unlock()
}

// recordCrashAndContinue 记一次崩溃, 返回是否还应继续重启 (未达熔断阈值)
func (m *Manager) recordCrashAndContinue(inst *Instance) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// 滑动窗口: 丢掉窗口外的旧崩溃
	kept := inst.crashes[:0]
	for _, t := range inst.crashes {
		if now.Sub(t) <= crashWindow {
			kept = append(kept, t)
		}
	}
	inst.crashes = append(kept, now)
	return len(inst.crashes) < crashThreshold
}

// onCircuitBreak 处理熔断: 进 Failed, 停止重启, 写审计; 若 Vital 则升级 Safety Trip
//
//	(机器停下来, 但内核活着, 审计活着, 用户还能操作)
func (m *Manager) onCircuitBreak(inst *Instance) {
	m.setState(inst, StateFailed)
	m.audit(inst, "service.circuit-break", true, nil)
	if m.log != nil {
		m.log.Error("service: component circuit-broke after repeated crashes",
			"unit", inst.Unit, "criticality", string(inst.Crit))
	}
	if inst.Crit == pkgregistry.CriticalityVital {
		// 绝不 kill nervud, 绝不 reboot: 只触发 Safety 锁存让机器停下来
		if m.log != nil {
			m.log.Error("service: VITAL component failed - escalating to Safety Trip", "unit", inst.Unit)
		}
		if m.safety != nil {
			m.safety.Trip()
		}
		m.audit(inst, "service.vital-escalation", true, nil)
	}
}

// backoffWait 指数退避等待, 可被停止/关停打断. 返回 false 表示应退出 supervisor
func (m *Manager) backoffWait(backoff *time.Duration, inst *Instance) bool {
	d := *backoff
	if next := d * 2; next <= m.backoffMax {
		*backoff = next
	} else {
		*backoff = m.backoffMax
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-inst.stopCh:
		m.setState(inst, StateStopped)
		return false
	case <-m.ctx.Done():
		m.setState(inst, StateStopped)
		return false
	}
}

// buildStartReq 从 Entry 和 Component 组装 StartSandboxedProcessRequest
//
// native: ExecStart = 包内 ELF; LD_LIBRARY_PATH 指向包内 native_lib_dir.
// jvm: ExecStart = 平台 JRE; -jar 指向包内 entry; -Djava.library.path 指向包内库.
// 两种 runtime 的包内路径都进 ContainedPaths, 由 authority.Validate 逐一核对在
// PackageRoot 之内
// readWritePaths 给出组件在 ProtectSystem=strict 下的可写路径集合.
//
// 默认只有自己的私有数据目录. 装包服务额外要 staging 根: nervud 在那底下
// 给它建 stage-* 目录让它解包, 而 strict 让整个文件系统只读 - 不在这个列表里
// 的话, 即便属主与权限都对, 写进去也是 read-only file system.
//
// 权限与挂载是两道独立的门. 此前只做了属主那道, 装包卡在这道上.
func (m *Manager) readWritePaths(e pkgregistry.Entry, dataDir string) []string {
	paths := []string{dataDir}
	// staging 根: 判据是 perm.pkg.admin, 与管理通道的准入判据同源.
	// 用 Allowed 而不是包名比对, 内核因此不需要认识任何具体的包
	if m.stagingRoot != "" && m.perms != nil &&
		m.perms.Allowed(e.Manifest.PackageID, PermissionPackageAdmin) {
		paths = append(paths, m.stagingRoot)
	}
	// 共享用户文档区: 声明了 perm.storage.user 的包才拿得到. 文件管理器,
	// 文件选择器和任何要打开用户文档的 app 靠它看到同一批文件.
	//
	// 判据同时用 GrantedPermissions (安装资格) 和 permission.Registry.Allowed
	//  (当前运行期决策), 而不是 manifest.Permissions (申请). USER_CONSENT
	// 权限只进入 GrantedPermissions 并不代表用户已同意; 只看这一层会在拒绝状态
	// 下仍把共享目录绑定进 mount namespace.
	//
	// 系统镜像包的 GrantedPermissions 由 pkgregistry.arbitrateSystemGrants 在
	// 启动扫描时算出, 动态安装包由 Install 的 Intersect 算出, 两条路都已填好.
	if m.inv.UserDataRoot != "" &&
		hasPermission(e, permStorageUser) &&
		m.perms != nil &&
		m.perms.Allowed(e.Manifest.PackageID, permStorageUser) {
		paths = append(paths, m.inv.UserDataRoot)
	}
	// 服务间共享区: 本包自己那个子目录可写.
	//
	// 给的是子目录而不是根: 根可写等于允许任意包在根下造目录, 那就绕开了
	// "一个包一个目录, 属主即写权"这条结构. 读别人的目录不需要 ReadWritePaths
	// - ProtectSystem=strict 只让文件系统只读, 不阻止读; 跨包读的隔离在本系统里
	// 只靠数据目录的 0700 实现, 而共享子目录是 0755, 本就设计成可读.
	//
	// 判据同 perm.storage.user: GrantedPermissions (安装资格) 与运行期 Allowed
	// 都要过. 只看前者会在用户拒绝后仍把目录绑进 mount namespace.
	if hasPermission(e, permStorageShared) &&
		m.perms != nil &&
		m.perms.Allowed(e.Manifest.PackageID, permStorageShared) {
		paths = append(paths, m.sharedDirsFor(e.Manifest.PackageID)...)
	}
	return paths
}

// sharedDirsFor 给出该包在共享区里可写的两个子目录. 与
// pkgregistry.provisionEntry 建的是同一批路径 - 两处对不上时症状是
// "目录建了但写不进去", 因此路径拼接必须只有这一种写法.
func (m *Manager) sharedDirsFor(packageID string) []string {
	var out []string
	if m.inv.SharedRuntimeRoot != "" {
		out = append(out, filepath.Join(m.inv.SharedRuntimeRoot, packageID))
	}
	if m.inv.SharedPersistRoot != "" {
		out = append(out, filepath.Join(m.inv.SharedPersistRoot, packageID))
	}
	return out
}

// hasPermission 报告某 Package 是否已被授予某权限.
//
// 读 GrantedPermissions 而非 manifest: 见 readWritePaths 的说明.
func hasPermission(e pkgregistry.Entry, perm string) bool {
	return slices.Contains(e.GrantedPermissions, perm)
}

func (m *Manager) buildStartReq(e pkgregistry.Entry, c pkgregistry.Component, unit string) (authority.StartSandboxedProcessRequest, error) {
	verDir := codeDir(m.inv, e)
	dataDir := filepath.Join(m.inv.DataRoot, e.Manifest.PackageID)
	entryPath := filepath.Join(verDir, c.Entry)

	req := authority.StartSandboxedProcessRequest{
		UnitName:   unit,
		Desc:       e.Manifest.PackageID + "/" + c.ID,
		UID:        e.UID,
		GID:        e.UID,
		WorkingDir: dataDir,
		BindToUnit: nervudUnit, // owner-death: nervud 死了组件也停 (修复)
		Limits: authority.ResourceLimits{
			MemoryMaxBytes:  c.Limits.MemoryMaxMB * 1024 * 1024,
			CPUQuotaPercent: c.Limits.CPUQuotaPercent,
			TasksMax:        uint64(c.Limits.TasksMax),
		},
		ReadWritePaths: m.readWritePaths(e, dataDir),
		ReadOnlyPaths:  []string{verDir},
		// 不能把整个 PackageRoot 设 InaccessiblePaths - 那会连组件自己的代码目录
		//  (verDir 在 PackageRoot 之下) 一起隐藏, 且 InaccessiblePaths 隐藏子目录后无法
		// 再靠嵌套 ReadOnlyPaths 恢复, native ELF / JAR /.so 全都读不到, 起不来.
		// 隔离依赖三层: 1. ProtectSystem=strict 让整个 fs 只读, 包括其它包代码目录;
		// 2. 各包数据目录使用独立 UID 和 0700; 3. registry 敏感目录设为 Inaccessible
		InaccessiblePaths: []string{registryDir},
		ContainedPaths:    []string{entryPath},
		// 只有系统镜像内置的包能碰真实设备节点: 驱动机器人硬件的 Provider
		//  (电机 / CAN / 串口) 必须看得到宿主 /dev, 而默认沙箱的
		// PrivateDevices+DevicePolicy=closed 会把它们全部挡掉 (与 UID 无关,
		// 提权到 root 也绕不开). 动态安装的包一律拿不到 - 它们的 Source 是
		// SourceDynamicInstall, 走 else 分支保持默认的封闭 /dev.
		AllowDeviceAccess: e.Source == pkgregistry.SourceSystemImage,
	}

	// Linux 层特权: capability 与额外 socket 地址族.
	//
	// 只给系统镜像来源的包, 与 AllowDeviceAccess 同一条规则. 动态安装的包
	// 即便在 manifest 里填了也拿不到 - 把 capability 交给任意第三方包等于沙箱
	// 不存在, 而这条判断必须在内核里做: manifest 是包自己写的, 不能让它
	// 自称有资格.
	//
	// 静默忽略而不是拒绝装载: 一个第三方包声明了 CAP_NET_ADMIN 不该让整个包
	// 装不上, 它只是拿不到而已. 真要用到那个能力时它会在运行期 EPERM,
	// 那个失败点比装不上更贴近问题.
	if e.Source == pkgregistry.SourceSystemImage {
		req.AmbientCapabilities = pkgregistry.EffectiveCapabilities(c)
		req.ExtraAddressFamilies = pkgregistry.EffectiveAddressFamilies(c)
		// 授予特权是要留痕的事. 审计里记下具体给了什么, 而不只是"起了个进程" -
		// 事后追一个包为什么能碰硬件时, 这一行是唯一的线索
		if len(req.AmbientCapabilities) > 0 || len(req.ExtraAddressFamilies) > 0 {
			m.aud.Record(context.Background(), audit.Event{
				Action:  "service.GrantLinuxPrivileges",
				Subject: e.Manifest.PackageID + "/" + c.ID,
				Detail:  pkgregistry.DescribePrivileges(req.AmbientCapabilities, req.ExtraAddressFamilies),
			})
		}
	}

	// 图形界面组件的额外接线. 判据用 type == app: 内核里 app 与 service 的区别
	// 就是"有没有界面" (app 由 Launcher 点开, service 在后台跑), 不需要再往
	// manifest 里加一个 gui 标志让人多填一处, 还可能填错
	if c.Type == pkgregistry.ComponentApp {
		req.BindReadOnlyPaths = append(req.BindReadOnlyPaths, x11SocketDir)
		req.Env = append(req.Env, displayEnv()...)
		// XAUTHORITY 指向的 cookie 文件通常在 root/用户 home 下, 而 ProtectHome=yes
		// 让那两处完全不可访问. 只传环境变量不把文件送进去, 组件会拿着一个
		// 打不开的路径去连 X, 报"No protocol specified" - 比不设更难查
		if xauth := os.Getenv("XAUTHORITY"); xauth != "" {
			req.BindReadOnlyPaths = append(req.BindReadOnlyPaths, xauth)
		}
	}

	var nativeLibDir string
	if c.NativeLibDir != "" {
		nativeLibDir = filepath.Join(verDir, c.NativeLibDir)
		req.ContainedPaths = append(req.ContainedPaths, nativeLibDir)
	}

	switch c.Runtime {
	case pkgregistry.RuntimeNative:
		req.Runtime = authority.RuntimeNative
		req.ExecPath = entryPath
		if nativeLibDir != "" {
			req.Env = append(req.Env, "LD_LIBRARY_PATH="+nativeLibDir)
		}
	case pkgregistry.RuntimeJVM:
		req.Runtime = authority.RuntimeJVM
		req.ExecPath = authority.PlatformJREExec
		if nativeLibDir != "" {
			req.Args = append(req.Args, "-Djava.library.path="+nativeLibDir)
		}
		// 把 JVM 的临时目录与 home 都指向本包私有数据目录.
		//
		// ## 为什么必须显式设
		//
		// 很多 JVM 库把原生库 (.so) 打在 jar 里, 运行时解压到磁盘再 dlopen.
		// Compose Desktop 的渲染后端 skiko 就是典型: libskiko-linux-*.so 有 30 MB,
		// 每次启动都要落盘. 默认落点有两个, 在本沙箱里都不可靠:
		//
		//  java.io.tmpdir -> /tmp PrivateTmp 给的私有 /tmp 可写, 但很多加固过
		//  的系统把宿主 /tmp 挂成 noexec, 私有 /tmp 继承它.
		//  那样.so 写得进去, dlopen 失败, 报
		//  UnsatisfiedLinkError - 与权限看着毫无关系
		//  user.home -> ~ ProtectHome=yes 让它完全不可访问
		//
		// 指向私有数据目录同时解决三件事: 它在 ReadWritePaths 里 (可写), 在
		// /var/lib 上 (不会是 noexec), 而且**持久** - 解压只发生一次,
		// 而不是每次开机搬 30 MB.
		//
		// 对不解压原生库的组件, 这两个属性只是换了个临时目录位置, 无副作用.
		req.Args = append(req.Args,
			"-Djava.io.tmpdir="+dataDir,
			"-Duser.home="+dataDir,
		)
		req.Args = append(req.Args, "-jar", entryPath)
	}
	return req, nil
}

// audit 记一条组件生命周期审计
func (m *Manager) audit(inst *Instance, action string, denied bool, err error) {
	if m.aud == nil {
		return
	}
	m.aud.Record(context.Background(), audit.Event{
		Action:  action,
		Subject: "pkg:" + inst.PackageID + " comp:" + inst.ComponentID,
		Denied:  denied,
		Err:     err,
		Detail:  inst.Unit,
	})
}

// codeDir 给出一个 Package 的代码目录.
//
// 两类包的布局不同, 不能共用一个拼法:
//
//	动态安装 <PackageRoot>/<pkg>/<version>/  多版本可共存, 升级时新旧并列
//	系统镜像 <SystemPackageRoot>/<pkg>/  无版本子目录, 跟随整镜像 OTA
//
// 系统镜像包没有版本子目录, 是因为它们不存在"多版本共存" - 整个镜像一起换.
// 内核的启动扫描也是按这个布局 glob 的 (scan.go: <root>/*/manifest.json).
//
// 无条件用 PackageRoot 拼会让系统包的 ExecStart 指向一个不存在的路径,
// systemd 在 step EXEC 失败 (203/EXEC) - 而错误信息只说"找不到可执行文件",
// 看不出是布局假设错了.
func codeDir(inv *authority.Invariants, e pkgregistry.Entry) string {
	if e.Source == pkgregistry.SourceSystemImage {
		return filepath.Join(inv.SystemPackageRoot, e.Manifest.PackageID)
	}
	return filepath.Join(inv.PackageRoot, e.Manifest.PackageID, e.ActiveVersion)
}
