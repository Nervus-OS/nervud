// Package service 本文件是组件实例的 supervisor 循环与崩溃分级处置（应用层架构决策 §5.4）。
//
// 每个运行中的实例由【一个】supervisor goroutine 独占监视：起进程 → 等退出 →
// 判定（预期停止 / 崩溃）→ 按 criticality 退避重启或熔断。阻塞调用
// （StartSandboxedProcess / WaitProcess）一律【不持 mu】；只有读写实例状态的
// 瞬间才短暂持 mu，避免一个卡住的 systemd 调用锁住整个 Manager。
package service

import (
	"context"
	"path/filepath"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

const (
	restartBackoffMin = 1 * time.Second
	restartBackoffMax = 60 * time.Second
	// crashWindow / crashThreshold：滑动窗口内崩溃达到阈值即熔断（§5.4）
	crashWindow    = 10 * time.Second
	crashThreshold = 5
	// startStopTimeout 给单次 StartSandboxedProcess/StopProcess 的上限——即便
	// systemd/D-Bus 卡住，也不让一个 supervisor 无限期阻塞。等一个长期运行组件
	// 退出（WaitProcess）则用 m.ctx，不设此上限
	startStopTimeout = 30 * time.Second

	// nervudUnit 是 nervud 自身的 systemd unit 名（部署形态，见 ND内核介绍）。组件
	// 瞬态 unit BindsTo 它，实现 owner-death：nervud 被 SIGKILL 后组件也被 systemd 停
	nervudUnit = "nervud.service"
	// registryDir 是 nervud 的可信状态目录，含 _grants/_devmode/ledger/uid 分配器。
	// 组件沙箱把它设 InaccessiblePaths，任何组件都读不到
	registryDir = "/var/lib/nervus/registry"
)

// unitName 由 (pkg, comp) 生成 systemd 瞬态 unit 名。pkg/comp 的字符集都禁止 '-'
// （manifest.validIDSegment），因此 "nervus-<pkg>-<comp>.service" 对不同组件唯一、
// 不会碰撞
func unitName(pkg, comp string) string {
	return "nervus-" + pkg + "-" + comp + ".service"
}

// effectiveCriticality 计算生效的 criticality：Ordinary 包声明高于 optional 一律
// 降级（§5.4：否则第三方 App 声明自己 vital、崩一下就把机器停死＝拒绝服务攻击）
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

// startLocked 建实例并起 supervisor。调用方必须持 m.mu
//
// 若该 key 已有一个终态实例（StateStopped/StateFailed——on-demand 组件被停止后，
// 或崩溃熔断后，都会停在 byKey 里而不是被摘除），这里【不】panic，而是当作全新
// 启动处理：旧 supervisor goroutine 在把状态置为终态之前已经真正停掉了对应的
// systemd unit（stopProc/drain 发生在 setState 之前；熔断则是重试耗尽、进程已不
// 在跑），所以外部一旦观察到终态，旧实例就不会再被那个 goroutine 写入，直接用新
// *Instance 覆盖 byKey/byUnit、起新 supervisor 是安全的——这正是 EnsureStarted 对
// 一个此前跑过又停止/熔断的 on-demand 组件重新拉起时必须支持的路径（见
// internal/endpoint 的 Resolve on-demand 拉起分支）
func (m *Manager) startLocked(e pkgregistry.Entry, c pkgregistry.Component) {
	key := componentKey{e.Manifest.PackageID, c.ID}
	if inst, ok := m.byKey[key]; ok && (inst.State == StateRunning || inst.State == StateStarting) {
		return // 已在跑，幂等
	}
	inst := &Instance{
		PackageID:   e.Manifest.PackageID,
		ComponentID: c.ID,
		UID:         e.UID,
		Unit:        unitName(e.Manifest.PackageID, c.ID),
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

// requestStop 通知实例的 supervisor：这是预期内停止，退出后不要重启（幂等）
func (m *Manager) requestStop(inst *Instance) {
	inst.stopOnce.Do(func() { close(inst.stopCh) })
}

// supervise 是单个实例的监视循环
func (m *Manager) supervise(inst *Instance, e pkgregistry.Entry, c pkgregistry.Component) {
	// done 在最后关闭：此刻 unit 已停、状态已定，ReloadPackage 可安全起新版本
	defer func() {
		close(inst.done)
		m.wg.Done()
	}()

	backoff := m.backoffMin
	for {
		req, err := m.buildStartReq(e, c, inst.Unit)
		if err != nil {
			// 构造请求就失败（如路径不合法）：重试也不会好，直接熔断
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

		// 起一个 goroutine 阻塞等退出；主循环 select 退出/停止/关停
		exitCh := make(chan error, 1)
		go func(handle authority.ProcessHandle) {
			_, werr := m.auth.WaitProcess(m.ctx, handle)
			exitCh <- werr
		}(h)

		select {
		case <-inst.stopCh:
			// 预期停止。【关键】由 supervisor 自己 StopProcess，不依赖外部调用方——
			// StopComponent/Stop 可能在本组件还处于 Starting、Handle 尚未落定时就快照
			// 到空 Handle 而没真正停掉它（§P0 修复）。此刻 supervisor 手里的 h 一定有效
			m.stopProc(h)
			m.drain(exitCh)
			m.setState(inst, StateStopped)
			return
		case <-m.ctx.Done():
			// 整体关停：同样由 supervisor 兜底停自己的 unit，避免 Starting 窗口漏停
			m.stopProc(h)
			m.drain(exitCh)
			m.setState(inst, StateStopped)
			return
		case werr := <-exitCh:
			// 自然退出。先复核是否其实是预期停止/关停竞态
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
			// 崩溃（service 不该自己退出）
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

// stopProc 停掉一个句柄对应的 systemd unit。用【独立】的有界 ctx 而非 m.ctx——
// 关停路径上 m.ctx 已被 cancel，用它 StopProcess 会立刻 ctx 失败、unit 停不掉。
// StopUnit 幂等，与外部 StopComponent/Stop 的调用重叠也无害
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

// drain 等 exitCh 或关停信号，避免 WaitProcess goroutine 泄漏也不永久阻塞
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

// recordCrashAndContinue 记一次崩溃，返回是否还应继续重启（未达熔断阈值）
func (m *Manager) recordCrashAndContinue(inst *Instance) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// 滑动窗口：丢掉窗口外的旧崩溃
	kept := inst.crashes[:0]
	for _, t := range inst.crashes {
		if now.Sub(t) <= crashWindow {
			kept = append(kept, t)
		}
	}
	inst.crashes = append(kept, now)
	return len(inst.crashes) < crashThreshold
}

// onCircuitBreak 处理熔断：进 Failed，停止重启，写审计；若 Vital 则升级 Safety Trip
// （§5.4：机器停下来，但内核活着、审计活着、用户还能操作）
func (m *Manager) onCircuitBreak(inst *Instance) {
	m.setState(inst, StateFailed)
	m.audit(inst, "service.circuit-break", true, nil)
	if m.log != nil {
		m.log.Error("service: component circuit-broke after repeated crashes",
			"unit", inst.Unit, "criticality", string(inst.Crit))
	}
	if inst.Crit == pkgregistry.CriticalityVital {
		// 绝不 kill nervud、绝不 reboot：只触发 Safety 锁存让机器停下来（§5.4）
		if m.log != nil {
			m.log.Error("service: VITAL component failed — escalating to Safety Trip", "unit", inst.Unit)
		}
		if m.safety != nil {
			m.safety.Trip()
		}
		m.audit(inst, "service.vital-escalation", true, nil)
	}
}

// backoffWait 指数退避等待，可被停止/关停打断。返回 false 表示应退出 supervisor
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

// buildStartReq 从 Entry+Component 组装 StartSandboxedProcessRequest（§3.5 / §5.2）
//
// native：ExecStart = 包内 ELF；LD_LIBRARY_PATH 指向包内 native_lib_dir。
// jvm：   ExecStart = 平台 JRE；-jar 指向包内 entry；-Djava.library.path 指向包内库。
// 两种 runtime 的包内路径都进 ContainedPaths，由 authority.Validate 逐一核对在
// PackageRoot 之内
func (m *Manager) buildStartReq(e pkgregistry.Entry, c pkgregistry.Component, unit string) (authority.StartSandboxedProcessRequest, error) {
	verDir := filepath.Join(m.inv.PackageRoot, e.Manifest.PackageID, e.ActiveVersion)
	dataDir := filepath.Join(m.inv.DataRoot, e.Manifest.PackageID)
	entryPath := filepath.Join(verDir, c.Entry)

	req := authority.StartSandboxedProcessRequest{
		UnitName:   unit,
		Desc:       e.Manifest.PackageID + "/" + c.ID,
		UID:        e.UID,
		GID:        e.UID,
		WorkingDir: dataDir,
		BindToUnit: nervudUnit, // owner-death：nervud 死了组件也停（§P0 修复）
		Limits: authority.ResourceLimits{
			MemoryMaxBytes:  c.Limits.MemoryMaxMB * 1024 * 1024,
			CPUQuotaPercent: c.Limits.CPUQuotaPercent,
			TasksMax:        uint64(c.Limits.TasksMax),
		},
		ReadWritePaths: []string{dataDir},
		ReadOnlyPaths:  []string{verDir},
		// 【不能】把整个 PackageRoot 设 InaccessiblePaths——那会连组件自己的代码目录
		// （verDir 在 PackageRoot 之下）一起隐藏，且 InaccessiblePaths 隐藏子目录后无法
		// 再靠嵌套 ReadOnlyPaths 恢复，native ELF / JAR / .so 全都读不到、起不来。
		// 隔离靠：① ProtectSystem=strict 让整个 fs 只读（含别的包代码目录）② 别的包数据
		// 目录 0700 归各自 UID，DAC 天然挡住 ③ 单独把 registry 敏感目录设 Inaccessible
		InaccessiblePaths: []string{registryDir},
		ContainedPaths:    []string{entryPath},
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
