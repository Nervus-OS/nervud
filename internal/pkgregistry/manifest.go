// 本文件是 manifest.json 的数据模型与结构性校验。
// 这里只做形状是否合法的纯校验，不碰文件系统、不做签名/digest 复核
// （签名见 signature.go/sigblock.go，digest 见 digest.go）
//
// 安全边界：package_id / component.id 会被用作 UID 分配键、
// 目录名、权限归属键与签名连续性键，且其中 package_id 会拼进记账文件名
// （scan.go 的 stateFilePath）。因此这里对二者做严格字符集校验，把路径写逃逸
// 这类洞堵在解析入口，而不是指望下游一定校验过
package pkgregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// manifestSchemaV1 是本版本认识的唯一 manifest schema 版本号
const manifestSchemaV1 = 1

// CurrentAPILevel 是本内核实现的 Platform API Level
//
// manifest 的 min_nervus_api 高于它即无法在本机运行 - 两段解析的第一段会先
// 用它给出 ErrPlatformTooOld，而不是让新 schema 的 manifest 撞上
// DisallowUnknownFields 后报一个含义模糊的未知字段
const CurrentAPILevel uint32 = 1

// NSOS Package 的 canonical ABI token。这些是 NSOS 包格式标识，
// 不是 Android NDK 名称（arm64-v8a 等），也不是裸 CPU 名（aarch64 等） - 后两类
// 一律拒绝，不做归一化
const (
	ABILinuxArm64  = "linux-arm64"
	ABILinuxArmv7  = "linux-armv7"
	ABILinuxX86_64 = "linux-x86_64"
)

func validABIToken(s string) bool {
	switch s {
	case ABILinuxArm64, ABILinuxArmv7, ABILinuxX86_64:
		return true
	default:
		return false
	}
}

var (
	// ErrEmptyPackageID manifest 缺少 Package ID
	ErrEmptyPackageID = errors.New("pkgregistry: manifest has empty package id")

	// ErrInvalidPackageID Package ID 含非法字符或形状（见 validPackageID）。
	// 这不只是命名规范：package_id 会拼进记账文件名，非法字符等于路径写逃逸
	ErrInvalidPackageID = errors.New("pkgregistry: manifest has invalid package id")

	// ErrInvalidComponentID Component ID 含非法字符或形状（见 validComponentID）
	ErrInvalidComponentID = errors.New("pkgregistry: manifest has invalid component id")

	// ErrEmptyVersion manifest 缺少版本号
	ErrEmptyVersion = errors.New("pkgregistry: manifest has empty version")

	// ErrInvalidVersion version 含非法字符或形状（见 validVersion）。version 会被
	// 拼成代码目录名 <PackageRoot>/<id>/<version>（install.go），非法字符等于让
	// 敌意 manifest 用 version="../com.victim/2.0" 把代码写进别的 Package 命名空间
	ErrInvalidVersion = errors.New("pkgregistry: manifest has invalid version")

	// ErrMissingVersionCode manifest 缺少 version_code（或为 0）。升级裁决只看
	// version_code，缺它就无法做防降级判断
	ErrMissingVersionCode = errors.New("pkgregistry: manifest has zero/absent version_code")

	// ErrUnsupportedSchema manifest 声明了本版本不认识的 schema 版本号
	ErrUnsupportedSchema = errors.New("pkgregistry: unsupported manifest schema")

	// ErrPlatformTooOld manifest 的 min_nervus_api 高于本机 Platform API Level
	ErrPlatformTooOld = errors.New("pkgregistry: platform api level too old for this package")

	// ErrInvalidABI supported_abis 为空、含未知或非 canonical token（含 Android NDK 名）
	ErrInvalidABI = errors.New("pkgregistry: manifest has empty or invalid supported_abis")

	// ErrNoComponents 一个 Package 必须至少声明一个 App 或 Service
	ErrNoComponents = errors.New("pkgregistry: manifest declares no components")

	// ErrNoDigests manifest 必须携带文件 digest 清单，否则完整性复核无从谈起
	ErrNoDigests = errors.New("pkgregistry: manifest has no file digests")

	// ErrDuplicateComponentID 同一 manifest 内两个 Component 共用一个 ID
	ErrDuplicateComponentID = errors.New("pkgregistry: duplicate component id in manifest")

	// ErrInvalidComponentType Component.Type 只能是 app 或 service
	ErrInvalidComponentType = errors.New("pkgregistry: component type must be app or service")

	// ErrInvalidRuntime Component.Runtime 只能是 native 或 jvm
	ErrInvalidRuntime = errors.New("pkgregistry: component runtime must be native or jvm")

	// ErrInvalidLaunchMode Component.LaunchMode 取值非法
	ErrInvalidLaunchMode = errors.New("pkgregistry: component has invalid launch_mode")

	// ErrLaunchModeTypeMismatch launch_mode 与 type 冲突：app 不能 always-on，
	// service 不能 manual
	ErrLaunchModeTypeMismatch = errors.New("pkgregistry: launch_mode incompatible with component type")

	// ErrInvalidCriticality Component.Criticality 取值非法
	ErrInvalidCriticality = errors.New("pkgregistry: component has invalid criticality")

	// ErrInvalidVisibility Export.Visibility 取值非法
	ErrInvalidVisibility = errors.New("pkgregistry: export has invalid visibility")

	// ErrEntryNotInDigests Component.Entry 未被 digests 清单覆盖 - 入口文件必须
	// 被签名/完整性复核覆盖，否则等于允许运行一个未经校验的可执行文件
	ErrEntryNotInDigests = errors.New("pkgregistry: component entry not covered by digests")

	// ErrIconNotInDigests manifest.icon 未被 digests 清单覆盖
	ErrIconNotInDigests = errors.New("pkgregistry: icon not covered by digests")

	// ErrUnsafeRelPath 一个应为包内相对路径的字段解析后逃出了包目录，
	// 或本身就是绝对路径
	ErrUnsafeRelPath = errors.New("pkgregistry: path escapes package directory")
)

// ComponentType 是 Component 的运行形态
type ComponentType string

const (
	ComponentApp     ComponentType = "app"
	ComponentService ComponentType = "service"
)

// Runtime 是 Component 的进程入口启动方式
//
// 注意：runtime 描述进程入口由谁启动，不是能不能有原生代码 - 两种 runtime
// 都可以携带 lib/<abi>/*.so 并经 JNI/Panama 或直接链接加载
type Runtime string

const (
	RuntimeNative Runtime = "native"
	RuntimeJVM    Runtime = "jvm"
)

func (r Runtime) valid() bool { return r == RuntimeNative || r == RuntimeJVM }

// LaunchMode 是 Component 的启动模式
type LaunchMode string

const (
	// LaunchAlwaysOn 内核就绪后拉起，崩溃退避重启（仅 service）
	LaunchAlwaysOn LaunchMode = "always-on"
	// LaunchOnDemand Resolve 到其 endpoint 时拉起，空闲超时停
	LaunchOnDemand LaunchMode = "on-demand"
	// LaunchManual 仅显式请求（Launcher 拉起 app）
	LaunchManual LaunchMode = "manual"
)

func (l LaunchMode) valid() bool {
	return l == LaunchAlwaysOn || l == LaunchOnDemand || l == LaunchManual
}

// Criticality 是 Component 的重要性分级
//
// 用有序字符串而不是在 internal/service 里另存一份 uint8 枚举：manifest 是
// criticality 的真源，两处各存一份会漂。service 的升级链用 Rank 比较
type Criticality string

const (
	CriticalityOptional Criticality = "optional"
	CriticalityRequired Criticality = "required"
	CriticalityVital    Criticality = "vital"
)

func (c Criticality) valid() bool {
	return c == CriticalityOptional || c == CriticalityRequired || c == CriticalityVital
}

// Rank 返回 criticality 的有序级别，供 service 升级链比较（optional<required<vital）
func (c Criticality) Rank() int {
	switch c {
	case CriticalityVital:
		return 2
	case CriticalityRequired:
		return 1
	default:
		return 0
	}
}

// Visibility 是 Export 的可见范围
type Visibility string

const (
	// VisibilityPackage 仅同 Package 内其它 Component 可 Resolve（需 perm.service.register.private）
	VisibilityPackage Visibility = "package"
	// VisibilityPublic 跨 Package 可见（需 perm.service.register，OEM+）
	VisibilityPublic Visibility = "public"
)

func (v Visibility) valid() bool { return v == VisibilityPackage || v == VisibilityPublic }

// Export 是一个 Component 对外提供的 Interface
type Export struct {
	Interface  string     `json:"interface"`
	Visibility Visibility `json:"visibility"`
}

// Feature 是 manifest 声明消费的机器人 Feature
type Feature struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

// RuntimeDeps 是运行时依赖声明
type RuntimeDeps struct {
	MinJavaRelease int `json:"min_java_release,omitempty"`
}

// ComponentLimits 是传给 systemd 的资源上限
//
// 内核按 trust 钳制这些值的上限，Ordinary 包不能给自己开无限额度 - 钳制在
// internal/service 落地，这里只做形状承载
type ComponentLimits struct {
	MemoryMaxMB     uint64 `json:"memory_max_mb,omitempty"`
	CPUQuotaPercent uint32 `json:"cpu_quota_percent,omitempty"`
	TasksMax        uint32 `json:"tasks_max,omitempty"`
}

// Component 是 manifest 里声明的一个可注册运行单元
type Component struct {
	ID           string          `json:"id"`
	Type         ComponentType   `json:"type"`
	Runtime      Runtime         `json:"runtime"`
	Entry        string          `json:"entry"`                      // 包内相对入口路径
	NativeLibDir string          `json:"native_lib_dir,omitempty"`   // 包内相对目录
	LaunchMode   LaunchMode      `json:"launch_mode"`                //
	Criticality  Criticality     `json:"criticality,omitempty"`      // 缺省 optional
	Disableable  bool            `json:"disableable,omitempty"`      // 生效值见 Entry.CanDisable
	Exports      []Export        `json:"exports,omitempty"`          //
	Interfaces   []string        `json:"interfaces,omitempty"`       // 请求消费的接口 ID
	IdleTimeout  int             `json:"idle_timeout_sec,omitempty"` // 仅 on-demand 有效
	Limits       ComponentLimits `json:"limits,omitempty"`
}

// Manifest 是 manifest.json 的解析结果
//
// Signer 故意不是一个 JSON 字段：它来自对分离签名的独立验证（见 signature.go），
// 不能让 manifest 自己在 JSON 里填一个 signer 字符串就自证身份
type Manifest struct {
	Schema          int               `json:"schema"`
	PackageID       string            `json:"package_id"`
	Label           string            `json:"label"`
	Labels          map[string]string `json:"labels,omitempty"`
	Icon            string            `json:"icon,omitempty"`
	Version         string            `json:"version"`
	VersionCode     uint64            `json:"version_code"`
	MinNervusAPI    uint32            `json:"min_nervus_api"`
	TargetNervusAPI uint32            `json:"target_nervus_api"`
	SupportedABIs   []string          `json:"supported_abis"`
	RuntimeDeps     RuntimeDeps       `json:"runtime_deps,omitempty"`
	Permissions     []string          `json:"permissions,omitempty"`
	UsesFeatures    []Feature         `json:"uses_features,omitempty"`
	Components      []Component       `json:"components"`
	Digests         map[string]string `json:"digests"` // 包内相对路径 -> sha256 hex

	Signer string `json:"-"`
}

// Component 按 ID 查一个组件，供 service/停用逻辑使用
func (m Manifest) Component(id string) (Component, bool) {
	for _, c := range m.Components {
		if c.ID == id {
			return c, true
		}
	}
	return Component{}, false
}

// ParseManifest 反序列化并做结构性校验，失败即整体拒绝
//
// 两段解析：
//  1. 宽松解码，先看 schema 与 min_nervus_api - 好在未知字段之前给出
//     schema 不认识 / 平台太旧这类更准确、可诊断的错误；否则新版本 manifest
//     在旧设备上只会撞上 DisallowUnknownFields 报一个含义模糊的未知字段
//  2. 严格解码全量（DisallowUnknownFields）：manifest 里出现本版本不认识的字段，
//     多半意味着更新版本 schema 写的 manifest，静默忽略等于假装理解，应当拒绝
func ParseManifest(data []byte) (Manifest, error) {
	var probe struct {
		Schema       int    `json:"schema"`
		MinNervusAPI uint32 `json:"min_nervus_api"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Manifest{}, fmt.Errorf("pkgregistry: probe manifest: %w", err)
	}
	if probe.Schema != manifestSchemaV1 {
		return Manifest{}, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedSchema, probe.Schema, manifestSchemaV1)
	}
	if probe.MinNervusAPI > CurrentAPILevel {
		return Manifest{}, fmt.Errorf("%w: manifest requires api %d, platform provides %d",
			ErrPlatformTooOld, probe.MinNervusAPI, CurrentAPILevel)
	}

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
	// ---- 顶层身份与结构（保持既有负测的触发顺序：id/version/components/digests）----
	if m.PackageID == "" {
		return ErrEmptyPackageID
	}
	if !validPackageID(m.PackageID) {
		return fmt.Errorf("%w: %q", ErrInvalidPackageID, m.PackageID)
	}
	if m.Version == "" {
		return ErrEmptyVersion
	}
	if !validVersion(m.Version) {
		return fmt.Errorf("%w: %q", ErrInvalidVersion, m.Version)
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

	// ---- 组件校验分两趟 ----
	// 第一趟只做身份结构：id 合法性、去重、type、入口路径安全与 digest 覆盖。
	// 第二趟才做字段取值：runtime/launch_mode/criticality/exports。分开是为了让
	// 重复 ID / 非法 type / 路径逃逸这类结构错误在任何字段取值错误之前先被报出，
	// 诊断更贴近真正的问题
	seenID := make(map[string]struct{}, len(m.Components))
	for _, c := range m.Components {
		if c.ID == "" {
			return fmt.Errorf("pkgregistry: component with empty id (entry %q)", c.Entry)
		}
		if !validComponentID(c.ID) {
			return fmt.Errorf("%w: %q", ErrInvalidComponentID, c.ID)
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
		if _, ok := m.Digests[c.Entry]; !ok {
			return fmt.Errorf("%w: component %q entry %q", ErrEntryNotInDigests, c.ID, c.Entry)
		}
	}
	for _, c := range m.Components {
		if !c.Runtime.valid() {
			return fmt.Errorf("%w: component %q runtime %q", ErrInvalidRuntime, c.ID, c.Runtime)
		}
		if !c.LaunchMode.valid() {
			return fmt.Errorf("%w: component %q launch_mode %q", ErrInvalidLaunchMode, c.ID, c.LaunchMode)
		}
		// app 不能 always-on；service 不能 manual
		if c.Type == ComponentApp && c.LaunchMode == LaunchAlwaysOn {
			return fmt.Errorf("%w: app %q cannot be always-on", ErrLaunchModeTypeMismatch, c.ID)
		}
		if c.Type == ComponentService && c.LaunchMode == LaunchManual {
			return fmt.Errorf("%w: service %q cannot be manual", ErrLaunchModeTypeMismatch, c.ID)
		}
		if c.Criticality != "" && !c.Criticality.valid() {
			return fmt.Errorf("%w: component %q criticality %q", ErrInvalidCriticality, c.ID, c.Criticality)
		}
		for _, e := range c.Exports {
			if e.Visibility != "" && !e.Visibility.valid() {
				return fmt.Errorf("%w: component %q export %q visibility %q",
					ErrInvalidVisibility, c.ID, e.Interface, e.Visibility)
			}
		}
		if c.NativeLibDir != "" && !validRelPath(c.NativeLibDir) {
			return fmt.Errorf("%w: component %q native_lib_dir %q", ErrUnsafeRelPath, c.ID, c.NativeLibDir)
		}
	}

	// ---- 顶层必填新字段（放在组件校验之后，让组件结构错误优先暴露）----
	if m.VersionCode == 0 {
		return ErrMissingVersionCode
	}
	if len(m.SupportedABIs) == 0 {
		return fmt.Errorf("%w: empty", ErrInvalidABI)
	}
	for _, abi := range m.SupportedABIs {
		if !validABIToken(abi) {
			return fmt.Errorf("%w: %q", ErrInvalidABI, abi)
		}
	}
	if m.Icon != "" {
		if !validRelPath(m.Icon) {
			return fmt.Errorf("%w: icon %q", ErrUnsafeRelPath, m.Icon)
		}
		if _, ok := m.Digests[m.Icon]; !ok {
			return fmt.Errorf("%w: %q", ErrIconNotInDigests, m.Icon)
		}
	}
	return nil
}

// validPackageID 报告 s 是否是一个安全的 Package ID：反向 DNS 风格
// seg(.seg)*，每段 [a-z][a-z0-9_]*，1..8 段，总长 <= 128
//
// 这不只是命名规范：package_id 会被 scan.go 的 stateFilePath 拼进记账文件名，
// 因此拒绝 '.' '..' '/' '\' NUL、大写、空段与超长。
// 只允许小写是刻意的 - 大小写不敏感文件系统上 "Foo" 与 "foo" 会指向同一文件，
// 埋下两个 Package 争一个记账文件的隐患
func validPackageID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	segs := strings.Split(s, ".")
	if len(segs) < 1 || len(segs) > 8 {
		return false
	}
	for _, seg := range segs {
		if !validIDSegment(seg) {
			return false
		}
	}
	return true
}

// validComponentID 报告 s 是否是一个安全的 Component ID：单段 [a-z][a-z0-9_]*， <= 64
func validComponentID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	return validIDSegment(s)
}

// validVersion 报告 s 是否是一个安全的版本字符串
//
// version 会被拼成代码目录名 <PackageRoot>/<id>/<version>，因此必须按目录名
// 安全性收紧：只允许 [A-Za-z0-9._+-]，长度 <= 64，
// 且拒绝 "."/".." 与含斜杠、反斜杠、NUL 的形状。否则 version="../com.victim/2.0"
// 经 filepath.Join 清理后会落进别的 Package 命名空间（ 同类洞）
func validVersion(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	if s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.' || c == '_' || c == '+' || c == '-':
			// ok
		default:
			return false
		}
	}
	return true
}

func validIDSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= 'a' && c <= 'z':
			// ok
		case i > 0 && (c >= '0' && c <= '9' || c == '_'):
			// ok（数字与下划线不能作首字符）
		default:
			return false
		}
	}
	return true
}

// validRelPath 报告 p 是否是一个安全的包内相对路径：非空、非绝对路径，
// 且 Clean 之后不会以 ".." 逃出包目录
//
// 这是纯字符串校验；真正的逃逸防护要等安装提交时由 authority 用
// openat2(RESOLVE_BENEATH) 兜底
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
