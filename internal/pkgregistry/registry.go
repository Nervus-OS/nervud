// 见 doc.go 的包说明
//
// 本文件是 pkgregistry 的权威内存态：装包/卸载/启动扫描之后，谁是已装
// Package、拿到了什么 UID 和信任 profile 的唯一真源。identity.Registry
// 只保存其中 ID/UID/Trust 的一份瘦投影用于 IPC 准入（见 module.go），
// 版本、manifest 全量内容等只在这里保存一份，不重复
package pkgregistry

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
)

// ErrDuplicatePackageID 快照里两个 Entry 共用同一个 Package ID
var ErrDuplicatePackageID = errors.New("pkgregistry: duplicate package id in registry snapshot")

// Entry 是一个已装 Package 的权威状态
type Entry struct {
	Manifest      Manifest
	ActiveVersion string
	UID           uint32
	Trust         identity.TrustProfile
	Source        Source
}

// Registry 是 pkgregistry 的权威内存态：Package ID -> Entry
//
// 照抄 identity.Registry 的写时复制 + 原子指针范式（读多写少：每次装包/
// 卸载/启动扫描才写，其余都是读），全量替换而不是增量增删——增量接口会
// 诱使调用方“先删后加”，中间存在一个查不到的窗口，架构上与 identity
// 面对的是同一类问题
//
// 零值不可用，必须经 NewRegistry 构造
type Registry struct {
	snap atomic.Pointer[snapshot]
}

type snapshot struct {
	byID map[string]Entry
}

func NewRegistry() *Registry {
	r := &Registry{}
	r.snap.Store(&snapshot{byID: map[string]Entry{}})
	return r
}

// Replace 原子替换整份 Registry
//
// 校验失败时整份拒绝、旧快照原样保留：宁可继续用上一份已知良好的状态，
// 也不要装载一份自相矛盾的（与 identity.Registry.Replace 同一理由）
//
// UID 校验复用 authority.DefaultInvariants().CheckUID 而不是在本包另存
// 一份 App UID 区段常量——两处各存一份、日后只改一处会悄悄漂移，而
// pkgregistry 本来就需要依赖 authority 的请求类型（见 module.go），
// 多依赖这一个只读校验函数不增加额外耦合面
func (r *Registry) Replace(entries []Entry) error {
	next := make(map[string]Entry, len(entries))
	for _, e := range entries {
		if e.Manifest.PackageID == "" {
			return fmt.Errorf("pkgregistry: entry with uid %d has empty package id", e.UID)
		}
		if err := authority.DefaultInvariants().CheckUID(e.UID); err != nil {
			return fmt.Errorf("pkgregistry: package %q: %w", e.Manifest.PackageID, err)
		}
		if !e.Trust.Valid() {
			return fmt.Errorf("pkgregistry: package %q has invalid trust profile %d",
				e.Manifest.PackageID, e.Trust)
		}
		if _, dup := next[e.Manifest.PackageID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicatePackageID, e.Manifest.PackageID)
		}
		next[e.Manifest.PackageID] = e
	}
	r.snap.Store(&snapshot{byID: next})
	return nil
}

// Lookup 按 Package ID 查 Entry
//
// 对未初始化的 Registry（零值 &Registry{} 或 typed-nil）fail-safe 返回
// “查无此包”而不是 panic——一个装配 bug 不该被放大成启动路径崩溃，
// 与 identity.Registry.Lookup 的理由相同
func (r *Registry) Lookup(id string) (Entry, bool) {
	if r == nil {
		return Entry{}, false
	}
	snap := r.snap.Load()
	if snap == nil {
		return Entry{}, false
	}
	e, ok := snap.byID[id]
	return e, ok
}

// List 返回当前全部 Entry 的快照副本
//
// 用途之一是启动扫描完成后批量投影给 identity.Registry.Replace（见
// module.go 的 projectIdentity），之一是诊断
func (r *Registry) List() []Entry {
	if r == nil {
		return nil
	}
	snap := r.snap.Load()
	if snap == nil {
		return nil
	}
	out := make([]Entry, 0, len(snap.byID))
	for _, e := range snap.byID {
		out = append(out, e)
	}
	return out
}

// Len 返回当前 Registry 里的 Package 数，供诊断与测试使用
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	snap := r.snap.Load()
	if snap == nil {
		return 0
	}
	return len(snap.byID)
}
