// 本文件定义权限登记表（Catalog）的形状：每个已注册权限 ID 声明拿到它至少
// 需要的信任 profile。Catalog 本身不裁决任何具体请求 - 裁决在 intersect.go
package permission

import (
	"fmt"

	"github.com/nervus-os/nervud/internal/identity"
)

// GrantMode 是一个权限怎么被授予
type GrantMode uint8

const (
	// GrantInstall 安装时静默授予（normal 权限）：只要 trust 够、装了就有
	GrantInstall GrantMode = iota
	// GrantUser 危险权限：安装只授予可请求资格，实际访问需运行期用户确认，
	// 且可随时撤销（我们独有、Android 也有的 dangerous 权限）
	GrantUser
	// GrantSignature 只按签名/trust 授予，用户不参与（如平台内部能力）
	GrantSignature
)

func (m GrantMode) valid() bool { return m == GrantInstall || m == GrantUser || m == GrantSignature }

// 权限组名。撤销 motion 组权限要联动 control 撤租 + 递增
// motion epoch，因此组名是裁决逻辑的一部分，用常量钉死
const (
	GroupMotion     = "motion"
	GroupCamera     = "camera"
	GroupMicrophone = "microphone"
	GroupStorage    = "storage"
	GroupLocation   = "location"
)

// CatalogEntry 是一条已注册权限的定义
type CatalogEntry struct {
	ID       string
	MinTrust identity.TrustProfile // 拿到这个权限至少需要的 trust profile
	Mode     GrantMode             // 怎么授予（install/user/signature）
	Group    string                // 权限组（camera/microphone/motion/...），空表示无组
	// RequireSignerRole 可选：只有该角色签名的包才能拿到这个权限，比单纯 trust
	// 等级更细。如 perm.authority.reboot 只给 platform-release。
	// 用字符串而非 pkgregistry.SignerRole 类型，避免 permission -> pkgregistry 依赖倒挂
	RequireSignerRole string
	// Description 供审计/诊断日志使用，不参与裁决
	Description string
}

// GrantState 是一个 (Package, 权限) 的运行期授予状态
type GrantState uint8

const (
	// GrantStateNotRequested 从未请求（GrantUser 权限的初始态）
	GrantStateNotRequested    GrantState = iota
	GrantStateGranted                    // 已授予
	GrantStateDenied                     // 用户拒绝过，还能再问
	GrantStateDeniedPermanent            // 用户勾了不再询问
)

func (s GrantState) valid() bool {
	return s == GrantStateNotRequested || s == GrantStateGranted ||
		s == GrantStateDenied || s == GrantStateDeniedPermanent
}

// Catalog 是权限定义表：每个已注册权限 ID 声明拿到它所需的最低信任 profile
//
// 零值 Catalog（nil map）视为"没有任何已注册权限"，所有请求权限交集出的结果
// 都是空集，而不是 panic - 未装配的 Catalog 是装配阶段的 bug，不该被放大成
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
		if !e.Mode.valid() {
			return Catalog{}, fmt.Errorf("permission: catalog entry %q has invalid grant mode %d", e.ID, e.Mode)
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
// 权限 ID 的正式命名空间与取值表尚未冻结。这里的最小集合只用于建立
// 请求权限、已注册权限与 trust 门槛的交集裁决，不代表已经设计完整的权限
// 分类体系 - 不要在没有产品侧输入之前往这里堆更多看起来完备的条目
//
// 本阶段不支持外部可写的权限定义文件：如果权限定义本身能被文件系统上的
// 内容修改，就等于把"谁能拿到什么权限"这条底线的控制权交给了文件写权限，
// 而不是签名链，这与"manifest 不能自称 system 完成提权"背后的
// 原则相悖
func DefaultCatalog() Catalog {
	cat, err := NewCatalog([]CatalogEntry{
		{
			ID:          "perm.diagnostics.read",
			MinTrust:    identity.TrustOrdinary,
			Mode:        GrantInstall,
			Description: "Read-only diagnostic information (placeholder)",
		},
		// perm.service.register 拆分：让用户应用的配套服务能
		// 服务自己的 app（.private，Ordinary 即可），同时保持普通包不能对外冒充系统
		// 能力（跨包 .register 仍需 OEM+）
		{
			ID:          "perm.service.register.private",
			MinTrust:    identity.TrustOrdinary,
			Mode:        GrantInstall,
			Description: "Register a Service visible only within the same Package",
		},
		{
			ID:          "perm.service.register",
			MinTrust:    identity.TrustOEM,
			Mode:        GrantInstall,
			Description: "Register a Service callable by other Packages (placeholder)",
		},
		// 共享用户文档区（Invariants.UserDataRoot）的读写权。文件管理器、文件
		// 选择器，以及任何要打开/保存用户文档的 app 需要它。
		//
		// 为什么是 GrantInstall 而不是 GrantUser：v1 不做运行期用户确认
		// （见 V1GrantAll）。等确认 UI 落地后这条应当改成 GrantUser + 独立
		// Group——"访问我的文件"正是典型的该问一句的权限。
		//
		// MinTrust 取 Ordinary：普通第三方 app 也该能存取用户文档，这不是特权。
		// 真正的约束在别处——目录是 sticky 的，谁也删不掉别人的东西。
		{
			ID:          "perm.storage.user",
			MinTrust:    identity.TrustOrdinary,
			Mode:        GrantInstall,
			Description: "Read/write the shared user documents area",
		},
		// 启动别的组件（Envelope 的 LaunchComponent(80)）。Launcher 与会话服务
		// 需要它。
		//
		// MinTrust 取 Platform：这不是普通应用该有的能力。能任意拉起组件意味着
		// 能绕过 on-demand 的节能语义（把所有服务全拉起来耗电），也能把一个刚被
		// 用户停用又启用的组件立刻拉起。给它 Platform 门槛，等于「只有随系统镜像
		// 发布、平台签名的包」才拿得到——第三方装的 Launcher 拿不到。
		{
			ID:          "perm.system.launch",
			MinTrust:    identity.TrustPlatform,
			Mode:        GrantInstall,
			Description: "Launch other installed components (launcher / session manager)",
		},
		// GrantUser 危险权限示例：安装只给可请求，实际访问需运行期用户确认、可撤销
		{
			ID:          "perm.camera.capture",
			MinTrust:    identity.TrustOrdinary,
			Mode:        GrantUser,
			Group:       GroupCamera,
			Description: "Access the camera (dangerous; requires user confirmation)",
		},
		{
			// motion 组：撤销时联动 control 撤租 + 递增 motion epoch
			ID:          "perm.motion.control",
			MinTrust:    identity.TrustOrdinary,
			Mode:        GrantUser,
			Group:       GroupMotion,
			Description: "Control robot motion (dangerous; requires user confirmation; revocation advances the motion epoch)",
		},
		{
			ID:          "perm.platform.control",
			MinTrust:    identity.TrustPlatform,
			Mode:        GrantSignature,
			Description: "Platform-level control capability (placeholder)",
		},
		{
			// RequireSignerRole 示例：最危险的操作只给 platform-release 签的包，
			// 连 platform-systemapp 签的 Launcher 也拿不到
			ID:                "perm.authority.reboot",
			MinTrust:          identity.TrustPlatform,
			Mode:              GrantSignature,
			RequireSignerRole: "platform-release",
			Description:       "Reboot the device (platform-release signer only)",
		},
		{
			// Safety 观察：读顶层状态 / motion epoch / 停止相位。
			//
			// 不是 Ordinary：安全态是判断机器此刻能不能动的依据，一个能持续
			// 轮询它的进程等于拿到了机器运行状态的高保真侧信道。
			ID:          "perm.safety.observe",
			MinTrust:    identity.TrustOEM,
			Mode:        GrantInstall,
			Description: "Observe safety state (top state, motion epoch, stop phase)",
		},
		{
			// Safety re-arm：解开停机锁存，让机器重新允许运动。
			//
			// 这是【全系统风险最高的一个权限】。运动权限误用只让机器动一下，
			// 这个误用让整套安全防护失效。因此与 reboot 同级：platform trust +
			// 只给 platform-release 签的包（即 nervus.safety.recovery 那类
			// 随镜像发布的恢复服务）。
			ID:                "perm.safety.rearm",
			MinTrust:          identity.TrustPlatform,
			Mode:              GrantSignature,
			RequireSignerRole: "platform-release",
			Description:       "Clear the safety latch and re-allow motion (platform-release signer only)",
		},
		{
			// 装包/卸载。调用 nervus.interface.pkg.manager 的门槛。
			//
			// 【为什么必须有这一条】：endpoint 的 Resolve 在接口目录里查不到
			// 条目时 requiredPermission 取空串，也就是【不设门槛】。没有它，
			// 任意一个 Ordinary 应用都能解析到 pkgmanagerd 并让它装包——
			// 装包是能往系统里放任意可执行文件的操作，那是提权。
			//
			// GrantUser 而不是 GrantInstall：装第三方软件这件事，用户必须
			// 当场知情。Android 的 REQUEST_INSTALL_PACKAGES 是同一判断。
			ID:          "perm.pkg.install",
			MinTrust:    identity.TrustOrdinary,
			Mode:        GrantUser,
			Description: "Install and uninstall packages (dangerous; requires user confirmation)",
		},
	})
	if err != nil {
		// 硬编码表必须自洽；如果连这里都校验不过，说明代码本身有 bug，
		// 而不是运行期可以恢复的状况
		panic(fmt.Sprintf("permission: DefaultCatalog is invalid: %v", err))
	}
	return cat
}
