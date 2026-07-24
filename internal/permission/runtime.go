// 本文件是运行期权限授予/撤销：GrantUser（危险）
// 权限的 (Package, 权限) -> GrantState 状态机，持久化到 registry 目录，并把撤销
// motion 组权限联动到 control 撤租 + 递增 motion epoch。
//
// 这是我们独有、Android 没有的立即撤销能力：撤销后靠写时复制 + 原子指针
// 让下一次 Allowed 立刻看到，无需等进程重启。
package permission

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/nervus-os/nervud/internal/audit"
)

const grantStateFile = "_grants.json"

// LeaseRevoker 是撤销 motion 组权限时对 control 的窄接口依赖：撤销某 Package 持有的
// 全部 ControlLease，由 control 递增 motion epoch。permission
// 不直接碰 gate - epoch 语义归 motion 撤销，不归权限。为 nil 时跳过（未接线阶段）
type LeaseRevoker interface {
	RevokeByPackage(pkgID string) error
}

// grantKey 是运行期授予状态的键
type grantKey struct {
	pkg  string
	perm string
}

// grantStore 是运行期授予状态的持久化容器
//
// 与 Registry 的 install-set（写时复制原子指针）分开：install-set 由 pkgregistry
// 全量投影驱动，而运行期状态由用户确认/撤销驱动，二者更新源不同。grantStore 用
// 普通锁 + 每次变更落盘 - 授予/撤销不是高频路径，不需要无锁读
type grantStore struct {
	mu       sync.RWMutex
	stateDir string       // 落盘目录（/var/lib/nervus/registry）；空表示不持久化（测试/未接线）
	revoker  LeaseRevoker // 撤销 motion 组权限时联动；可 nil
	aud      audit.Recorder
	states   map[grantKey]GrantState
}

func newGrantStore() *grantStore {
	return &grantStore{states: make(map[grantKey]GrantState)}
}

// diskGrant 是落盘 JSON 的一条记录
type diskGrant struct {
	PackageID  string     `json:"package_id"`
	Permission string     `json:"permission"`
	State      GrantState `json:"state"`
}

// load 从 stateDir 读回运行期授予状态；文件不存在或损坏都当作空（保守：读不出
// 来的授予绝不能被当成已授予）
func (g *grantStore) load() {
	if g.stateDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(g.stateDir, grantStateFile))
	if err != nil {
		return
	}
	var recs []diskGrant
	if err := json.Unmarshal(data, &recs); err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range recs {
		if r.PackageID == "" || r.Permission == "" || !r.State.valid() {
			continue
		}
		g.states[grantKey{r.PackageID, r.Permission}] = r.State
	}
}

// state 返回 (pkg, perm) 的运行期状态；无记录即 NotRequested
func (g *grantStore) state(pkg, perm string) GrantState {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s, ok := g.states[grantKey{pkg, perm}]
	if !ok {
		return GrantStateNotRequested
	}
	return s
}

// persistLocked 把当前全部状态原子落盘（调用方持写锁）
func (g *grantStore) persistLocked() error {
	if g.stateDir == "" {
		return nil
	}
	recs := make([]diskGrant, 0, len(g.states))
	for k, s := range g.states {
		recs = append(recs, diskGrant{PackageID: k.pkg, Permission: k.perm, State: s})
	}
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return fmt.Errorf("permission: encode grants: %w", err)
	}
	if err := os.MkdirAll(g.stateDir, 0o700); err != nil {
		return fmt.Errorf("permission: create grant state dir: %w", err)
	}
	return writeFileAtomic(filepath.Join(g.stateDir, grantStateFile), data, 0o600)
}

// set 更新 (pkg, perm) 的运行期状态并落盘。若这是把一个 motion 组权限转为非授予
// （撤销/拒绝），联动 revoker 撤租 + 递增 motion epoch
//
// isMotionGroup 由调用方（Registry，持有 Catalog）判定后传入 - grantStore 自己不持
// Catalog，避免它既管状态又管定义两件事
func (g *grantStore) set(pkg, perm string, state GrantState, isMotionGroup bool) error {
	g.mu.Lock()
	key := grantKey{pkg, perm}
	prev, had := g.states[key]
	g.states[key] = state
	if err := g.persistLocked(); err != nil {
		// 落盘失败即回滚内存，绝不让内存态领先磁盘（重启后磁盘旧值会赢，造成不一致）
		if had {
			g.states[key] = prev
		} else {
			delete(g.states, key)
		}
		g.mu.Unlock()
		return err
	}
	g.mu.Unlock()

	// 从已授予转到非授予= 撤销。motion 组权限撤销必须让 control 撤掉该包
	// 的全部 lease（含递增 epoch），否则已拿到 lease 的 App 还能继续让机器人动
	revoked := prev == GrantStateGranted && state != GrantStateGranted
	if revoked && isMotionGroup && g.revoker != nil {
		if rerr := g.revoker.RevokeByPackage(pkg); rerr != nil && g.aud != nil {
			g.aud.Record(context.Background(), audit.Event{
				Action: "permission.revoke.motion", Subject: pkg, Denied: true, Err: rerr,
			})
		}
	}
	if g.aud != nil {
		g.aud.Record(context.Background(), audit.Event{
			Action:  "permission.SetRuntimeState",
			Subject: pkg,
			Detail:  fmt.Sprintf("%s state=%d (was %d)", perm, state, prev),
		})
	}
	return nil
}

// clearPackage 删除某 Package 的全部运行期授予状态并落盘。卸载时调用 - 否则同 ID
// 重装会继承旧的危险权限授予（ 修复）
func (g *grantStore) clearPackage(pkg string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	changed := false
	for k := range g.states {
		if k.pkg == pkg {
			delete(g.states, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return g.persistLocked()
}

// writeFileAtomic 原子写文件（先临时文件再 rename）。permission 的运行期授予状态
// 是 nervud 自有 registry 目录里的记账，不跨信任边界，走标准库 os（同
// pkgregistry.writeFileAtomic 的理由）
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-grants-*")
	if err != nil {
		return fmt.Errorf("permission: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("permission: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("permission: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("permission: close temp: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("permission: chmod temp: %w", err)
	}
	return os.Rename(tmpPath, path)
}
