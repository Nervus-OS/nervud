// 见 doc.go 的包说明
//
// 本文件定义权限登记表（Catalog）的形状：每个已注册权限 ID 声明拿到它至少
// 需要的信任 profile。Catalog 本身不裁决任何具体请求——裁决在 intersect.go
package permission

import (
	"fmt"

	"github.com/nervus-os/nervud/internal/identity"
)

// CatalogEntry 是一条已注册权限的定义
type CatalogEntry struct {
	ID       string
	MinTrust identity.TrustProfile // 拿到这个权限至少需要的 trust profile
	// Description 供审计/诊断日志使用，不参与裁决
	Description string
}

// Catalog 是权限定义表：每个已注册权限 ID 声明拿到它所需的最低信任 profile
//
// 零值 Catalog（nil map）视为"没有任何已注册权限"，所有请求权限交集出的结果
// 都是空集，而不是 panic——未装配的 Catalog 是装配阶段的 bug，不该被放大成
// 运行期崩溃，与 identity.Registry/pkgregistry.Registry 对未初始化状态的
// fail-safe 处理同一思路
type Catalog struct {
	entries map[string]CatalogEntry
}

// NewCatalog 校验并构造一份 Catalog
//
// 校验失败即整体拒绝：一份自相矛盾的权限定义表（重复 ID、空 ID、非法 trust）
// 不该被静默接受后在运行期才暴露成裁决错误
func NewCatalog(entries []CatalogEntry) (Catalog, error) {
	m := make(map[string]CatalogEntry, len(entries))
	for _, e := range entries {
		if e.ID == "" {
			return Catalog{}, fmt.Errorf("permission: catalog entry has empty id")
		}
		if !e.MinTrust.Valid() {
			return Catalog{}, fmt.Errorf("permission: catalog entry %q has invalid min trust %d", e.ID, e.MinTrust)
		}
		if _, dup := m[e.ID]; dup {
			return Catalog{}, fmt.Errorf("permission: duplicate catalog entry %q", e.ID)
		}
		m[e.ID] = e
	}
	return Catalog{entries: m}, nil
}

// Lookup 按权限 ID 查定义
//
// 对零值 Catalog（nil map）同样 fail-safe 返回未登记，而不是 panic
func (c Catalog) Lookup(id string) (CatalogEntry, bool) {
	e, ok := c.entries[id]
	return e, ok
}

// Len 返回已登记的权限数，供诊断与测试使用
func (c Catalog) Len() int { return len(c.entries) }

// DefaultCatalog 返回编译期硬编码的最小权限定义表
//
// 权限 ID 的正式命名空间与取值表没有任何产品侧文档拍板（同一处理方式见
// pkgregistry/signature.go 对签名根格式的 stub）。这里给的几个 ID 只是把
// "请求 ∩ 已注册 ∩ trust 门槛"这条裁决链路立住，不代表已经设计完整的权限
// 分类体系——不要在没有产品侧输入之前往这里堆更多看起来完备的条目
//
// 本阶段不支持外部可写的权限定义文件：如果权限定义本身能被文件系统上的
// 内容修改，就等于把"谁能拿到什么权限"这条底线的控制权交给了文件写权限，
// 而不是签名链，这与架构 §7"manifest 不能自称 system 完成提权"背后的
// 原则相悖
func DefaultCatalog() Catalog {
	cat, err := NewCatalog([]CatalogEntry{
		{
			ID:          "perm.diagnostics.read",
			MinTrust:    identity.TrustOrdinary,
			Description: "只读诊断信息（占位）",
		},
		{
			ID:          "perm.service.register",
			MinTrust:    identity.TrustOEM,
			Description: "注册可被其它 Package 调用的 Service（占位）",
		},
		{
			ID:          "perm.platform.control",
			MinTrust:    identity.TrustPlatform,
			Description: "平台级控制能力（占位）",
		},
	})
	if err != nil {
		// 硬编码表必须自洽；如果连这里都校验不过，说明代码本身有 bug，
		// 而不是运行期可以恢复的状况
		panic(fmt.Sprintf("permission: DefaultCatalog is invalid: %v", err))
	}
	return cat
}
