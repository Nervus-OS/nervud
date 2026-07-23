// 见 doc.go 的包说明
//
// 本文件是 manifest.json 的数据模型与结构性校验。架构 §8 规定 manifest 至少
// 包含 Package ID、版本、签名者、文件 digest 清单、请求权限和 components[]；
// 这里只做“形状是否合法”的纯校验，不碰文件系统、不做签名/digest 复核
// （签名见 signature.go，digest 见 digest.go）
package pkgregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

var (
	// ErrEmptyPackageID manifest 缺少 Package ID
	ErrEmptyPackageID = errors.New("pkgregistry: manifest has empty package id")

	// ErrEmptyVersion manifest 缺少版本号
	ErrEmptyVersion = errors.New("pkgregistry: manifest has empty version")

	// ErrNoComponents 一个 Package 必须至少声明一个 App 或 Service
	// （架构 §7："一个 Package 可以只声明 App、只声明 Service，或同时声明"——
	// 但不能一个都不声明，那样的 Package 没有任何可运行形态）
	ErrNoComponents = errors.New("pkgregistry: manifest declares no components")

	// ErrNoDigests manifest 必须携带文件 digest 清单，否则完整性复核无从谈起
	ErrNoDigests = errors.New("pkgregistry: manifest has no file digests")

	// ErrDuplicateComponentID 同一 manifest 内两个 Component 共用一个 ID
	ErrDuplicateComponentID = errors.New("pkgregistry: duplicate component id in manifest")

	// ErrInvalidComponentType Component.Type 只能是 app 或 service（架构 §7），
	// 不再制造第三种可注册组件
	ErrInvalidComponentType = errors.New("pkgregistry: component type must be app or service")

	// ErrUnsafeRelPath 一个应为“包内相对路径”的字段解析后逃出了包目录，
	// 或本身就是绝对路径。入口路径解析后必须仍位于 Package 目录内（架构 §8），
	// digest 清单的键同样是包内相对路径，必须满足同一条规则——否则
	// 完整性复核会去比对包目录之外的文件
	ErrUnsafeRelPath = errors.New("pkgregistry: path escapes package directory")
)

// ComponentType 是 Component 的运行形态。nervud 外部组件只有这两种（架构 §7），
// “系统/普通”是信任 profile，不是第三种类型
type ComponentType string

const (
	ComponentApp     ComponentType = "app"
	ComponentService ComponentType = "service"
)

// Component 是 manifest 里声明的一个可注册运行单元
type Component struct {
	ID         string        `json:"id"`
	Type       ComponentType `json:"type"`
	Entry      string        `json:"entry"`       // 包内相对入口路径
	Runtime    string        `json:"runtime"`     // 如 "native"/"jvm"
	LaunchMode string        `json:"launch_mode"` // 如 "on-demand"/"always-on"
	// Interfaces 是该 Component 请求的接口 ID 列表；具体权限裁决与接口版本
	// 协商属于运行期（resource/endpoint），这里只记录“申请了什么”
	Interfaces []string `json:"interfaces,omitempty"`
}

// Manifest 是 manifest.json 的解析结果
//
// Signer 故意不是一个 JSON 字段：它来自对分离签名的独立验证（见 signature.go），
// 不能让 manifest 自己在 JSON 里填一个 signer 字符串就自证身份——那等于允许
// 自签
type Manifest struct {
	PackageID   string            `json:"package_id"`
	Version     string            `json:"version"`
	Digests     map[string]string `json:"digests"` // 包内相对路径 -> sha256 hex
	Permissions []string          `json:"permissions,omitempty"`
	Components  []Component       `json:"components"`

	Signer string `json:"-"`
}

// ParseManifest 反序列化并做结构性校验，失败即整体拒绝
//
// 用 DisallowUnknownFields：manifest 里出现本版本不认识的字段，多半意味着
// 一份更新版本 schema 写的 manifest，静默忽略未知字段等于假装理解了它，
// 应当拒绝而不是“尽量读懂”
func ParseManifest(data []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("pkgregistry: decode manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (m Manifest) validate() error {
	if m.PackageID == "" {
		return ErrEmptyPackageID
	}
	if m.Version == "" {
		return ErrEmptyVersion
	}
	if len(m.Components) == 0 {
		return ErrNoComponents
	}
	if len(m.Digests) == 0 {
		return ErrNoDigests
	}

	for rel := range m.Digests {
		if !validRelPath(rel) {
			return fmt.Errorf("%w: digest path %q", ErrUnsafeRelPath, rel)
		}
	}

	seenID := make(map[string]struct{}, len(m.Components))
	for _, c := range m.Components {
		if c.ID == "" {
			return fmt.Errorf("pkgregistry: component with empty id (entry %q)", c.Entry)
		}
		if _, dup := seenID[c.ID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateComponentID, c.ID)
		}
		seenID[c.ID] = struct{}{}

		if c.Type != ComponentApp && c.Type != ComponentService {
			return fmt.Errorf("%w: component %q has type %q", ErrInvalidComponentType, c.ID, c.Type)
		}
		if !validRelPath(c.Entry) {
			return fmt.Errorf("%w: component %q entry %q", ErrUnsafeRelPath, c.ID, c.Entry)
		}
	}
	return nil
}

// validRelPath 报告 p 是否是一个安全的包内相对路径：非空、非绝对路径，
// 且 Clean 之后不会以 ".." 逃出包目录
//
// 这是纯字符串校验（manifest 解析阶段包目录还不存在），和
// authority.Invariants.CheckContained 的三层防线是同一个思路的包内版本：
// 真正的逃逸防护要等安装提交时由 authority 用 openat2(RESOLVE_BENEATH) 兜底
func validRelPath(p string) bool {
	if p == "" || path.IsAbs(p) {
		return false
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return false
	}
	return true
}
