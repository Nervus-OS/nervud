// Package adminwire 是 nervud 特权管理通道 (nervusctl <-> nervud) 的线格式与客户端.
//
// 它刻意是一个叶子包: 只依赖标准库与 net, 不 import 任何 nervud 内核模块
//
//	(pkgregistry/permission/authority...). 这样 cmd/nervusctl 能只链接这一小片
//
// 代码, 而不是把整个内核 TCB 拖进 CLI 二进制. 服务端 (internal/admin) 与客户端
//
//	(cmd/nervusctl) 共用本包的 Request/Response/编解码, 保证两侧永不漂移.
//
// 这条通道不是 App 面向的跨语言控制面; 后者只使用 nervus-ipc 的冻结 proto,
// 避免出现两个不兼容的 wire 真源. 本通道是 nervud 与其同仓 Go 特权
// 运维工具之间的内部边界: 单进程写者仍是 nervud, nervusctl 只是把命令投递过去.
// 因此这里用长度前缀 + JSON (对 Go <-> Go, 低频, root-only 的运维面足够), 不引入
// proto/method_id 那套跨语言机制.
//
// 帧格式: 4 字节大端长度 N + N 字节 JSON. 与 internal/ipc/frame.go 同布局, 但本包
// 自持一份最小实现, 不 import internal/ipc (那会把内核依赖拖进 CLI).
package adminwire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// 管理命令标识. 服务端按 Request.Cmd 分派; 未知命令回 CodeBadRequest.
const (
	// CmdBeginStaging 请求 nervud 在其掌控的 staging 根下新建一个空目录, 返回
	// 绝对路径. CLI 随后把.nspkg 解包进去, 再发 CmdInstall. 由 nervud 建目录
	//  (而非 CLI 自己在任意位置建) 保证: 位置与 PackageRoot 同一文件系统 (安装
	// 期 renameat2 才能成功), 属主/权限受控, 且 install 时的路径逃逸校验有明确
	// 的必须是我发出的目录判据.
	CmdBeginStaging = "begin-staging"
	// CmdInstall 触发对一个已 staging 目录的安装. 签名/digest/裁决全部在 nervud
	// 的 pkgregistry 里复核 - CLI 不做任何安全判定.
	CmdInstall = "install"
	// CmdUninstall 卸载一个动态安装的 Package.
	CmdUninstall = "uninstall"
	// CmdList 列出当前已装 Package.
	CmdList = "list"
	// CmdSetEnabled 停用/启用一个 Component.
	CmdSetEnabled = "set-enabled"
	// CmdSetPermission 设置一个运行期 (GrantUser) 权限的授予状态 (grant/revoke).
	CmdSetPermission = "set-permission"
	// CmdInspect 只解析一个已 staging 目录, 回报它申请的 USER_CONSENT 权限,
	// 【不安装, 不改任何状态】.
	//
	// 安装确认屏用它: 用户必须在装之前看到这个包要什么权限, 而待装的包还不在
	// Catalog 里, 没有任何已有命令能查到.
	//
	// 与 CmdInstall 共用同一个 staging 目录: 确认屏先 inspect 再 install, 两次
	// 指的必须是同一棵树. 各自 staging 一次的话, 中间就出现一个"看的是 A,
	// 装的是 B"的缝 - 而用户看到的权限清单来自 A.
	CmdInspect = "inspect"
)

// 授予状态的 wire 表示. 与 permission.GrantState 一一对应, 但本包不 import
// permission (保持叶子包), 映射由服务端完成.
const (
	GrantStateNotRequested    = "not-requested"
	GrantStateGranted         = "granted"
	GrantStateDenied          = "denied"
	GrantStateDeniedPermanent = "denied-permanent"
)

// 风险等级的 wire 表示. 与 ipcv1.RiskClass 一一对应, 但本包不 import ipcv1
// (保持叶子包), 映射由服务端完成 - 与 GrantState 同一形态.
//
// 用字符串而不是数字: 这条通道的另一端是 pkgmanagerd 手抄的一份结构体, 而
// JSON 里一个裸数字改了枚举顺序就会静默变成另一档风险. 字符串写岔会得到一个
// 空值, 界面按"未知风险"处理, 不会把 CRITICAL_SAFETY 显示成 NORMAL.
const (
	RiskClassUnspecified      = ""
	RiskClassNormal           = "normal"
	RiskClassPrivacySensitive = "privacy-sensitive"
	RiskClassPhysicalControl  = "physical-control"
	RiskClassCriticalSafety   = "critical-safety"
)

// 机器可读的结果码. CLI 据此决定退出码/措辞; Message 只作人类可读补充.
const (
	CodeOK           = "ok"
	CodeBadRequest   = "bad-request"  // 命令/参数不合法 (含路径逃逸)
	CodeUnauthorized = "unauthorized" // 对端不是被许可的运维身份
	CodeNotFound     = "not-found"    // 目标 Package/Component 不存在
	CodeFailed       = "failed"       // 底层操作失败 (安装裁决拒绝, IO 错误...)
)

// Request 是 CLI -> nervud 的一条命令. 一条连接一条命令 (发一个 Request, 收一个
// Response, 随即关闭), 不做长连接状态机 - 运维面低频, 简单胜过复用.
type Request struct {
	Cmd         string `json:"cmd"`
	StagingDir  string `json:"staging_dir,omitempty"`
	PackageID   string `json:"package_id,omitempty"`
	ComponentID string `json:"component_id,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	Permission  string `json:"permission,omitempty"`
	GrantState  string `json:"grant_state,omitempty"`

	// ConsentedPermissions 随 install 携带: 用户在安装确认屏上点头的那批权限.
	//
	// 内核只把它当上限, 真正落库的是它与安装期授予集合以及 USER_CONSENT 这一档
	// 的交集 (见 pkgregistry.Module.applyInstallConsent), 因此这个字段夸大无害.
	// 省略即"没有任何权限被同意", 装包照常进行
	ConsentedPermissions []string `json:"consented_permissions,omitempty"`
}

// Response 是 nervud -> CLI 的结果. OK=false 时 Code/Message 说明原因.
type Response struct {
	OK         bool          `json:"ok"`
	Code       string        `json:"code,omitempty"`
	Message    string        `json:"message,omitempty"`
	StagingDir string        `json:"staging_dir,omitempty"` // begin-staging 的产物
	Package    *PackageInfo  `json:"package,omitempty"`     // install 的产物
	Packages   []PackageInfo `json:"packages,omitempty"`    // list 的产物
	Inspect    *InspectInfo  `json:"inspect,omitempty"`     // inspect 的产物
}

// InspectInfo 是一次只读检视的结果 (inspect 的产物).
//
// 与 PackageInfo 刻意分开: 那份描述的是【已装】包的状态 (trust, source, 已授予
// 权限), 而这份描述的是一个【尚未安装】的候选包 —— 它还没有 trust 裁决结果,
// 也还没有任何已授予权限. 复用同一个类型会让两种含义不同的空字段混在一起.
type InspectInfo struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	VersionCode uint64 `json:"version_code"`

	// ConsentPermissions 是本包申请的, 需要用户点头的敏感权限.
	// 已由 nervud 按 Catalog 定义过滤成 USER_CONSENT 那一档.
	ConsentPermissions []ConsentPermissionInfo `json:"consent_permissions,omitempty"`
}

// ConsentPermissionInfo 是确认屏要展示的一条待同意权限.
//
// 文案由内核从 Catalog 的权限定义里取出, 而不是由界面写死: 第三方包可以定义
// 自己的权限, 界面不可能预先知道它们的名称与说明.
//
// RiskClass 用 wire 上的字符串而不是数字: 本包是叶子包, 不 import ipcv1
// (与 GrantState 同一理由), 映射由服务端完成.
type ConsentPermissionInfo struct {
	ID              string `json:"id"`
	DisplayNameZhCN string `json:"display_name_zh_cn,omitempty"`
	DisplayNameEN   string `json:"display_name_en,omitempty"`
	DescriptionZhCN string `json:"description_zh_cn,omitempty"`
	DescriptionEN   string `json:"description_en,omitempty"`
	RiskClass       string `json:"risk_class,omitempty"`
}

// PackageInfo 是一个已装 Package 的对外投影 (install 结果 / list 项).
type PackageInfo struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	VersionCode uint64   `json:"version_code"`
	Trust       string   `json:"trust"`
	Source      string   `json:"source"`
	Granted     []string `json:"granted,omitempty"`  // 已授予权限 (供人确认)
	Disabled    []string `json:"disabled,omitempty"` // 已停用 Component
}

// MaxMessageBytes 是单条 JSON 消息的硬上限. 管理消息都很小 (install 只带一个路径,
// list 结果与 Package 数成正比), 1 MiB 远够, 又能挡住畸形长度前缀.
const MaxMessageBytes = 1 << 20

const lengthPrefixBytes = 4

// ErrMessageTooLarge 长度前缀超过硬上限.
var ErrMessageTooLarge = errors.New("adminwire: message exceeds hard limit")

// WriteTo 把 v 编码为 JSON 并以4 字节长度 + 正文写出. 服务端写 Response,
// 客户端写 Request 都走它.
func WriteTo(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("adminwire: marshal: %w", err)
	}
	if len(body) > MaxMessageBytes {
		return fmt.Errorf("%w: %d > %d", ErrMessageTooLarge, len(body), MaxMessageBytes)
	}
	var hdr [lengthPrefixBytes]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("adminwire: write header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("adminwire: write body: %w", err)
	}
	return nil
}

// ReadFrom 读满一条4 字节长度 + 正文并解码进 v. 服务端读 Request, 客户端读
// Response 都走它. 长度超限即报错 (不为攻击者自称的正文分配缓冲).
func ReadFrom(r io.Reader, v any) error {
	var hdr [lengthPrefixBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // 含 io.EOF: 对端关闭
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("adminwire: zero-length message")
	}
	if n > MaxMessageBytes {
		return fmt.Errorf("%w: %d > %d", ErrMessageTooLarge, n, MaxMessageBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// DefaultSockPath 是 nervud 管理通道的固定路径. 与 App 控制面
//
//	(/run/nervus/nervud.sock) 分开: 那条面向 App (UID 落在 App 段), 本条面向
//
// root/运维 (0600), 两套准入规则不混.
const DefaultSockPath = "/run/nervus/nervud-admin.sock"

// dialTimeout / ioTimeout 给 CLI 侧一条不会永久挂起的路径. 管理命令都很快;
// 一旦 nervud 没响应, CLI 应尽快报错退出而不是卡住运维脚本.
const (
	dialTimeout = 5 * time.Second
	ioTimeout   = 30 * time.Second // install 触发的裁决/落盘可能稍慢, 留足余量
)

// Client 是 nervusctl 侧的最小客户端. 不常驻, 不持有任何状态 - 每条命令一次
// Dial -> 写 -> 读 -> 关 (真源永远是 nervud 进程内的 Registry, CLI 只投递).
type Client struct {
	sockPath string
}

// NewClient 构造一个指向 sockPath 的客户端.
func NewClient(sockPath string) *Client {
	if sockPath == "" {
		sockPath = DefaultSockPath
	}
	return &Client{sockPath: sockPath}
}

// Do 执行一条命令: 连, 写 Request, 读 Response, 关. 传输失败返回 error;
// 业务失败 (OK=false) 不作为 error 返回, 交给调用方按 Response.Code 处理.
func (c *Client) Do(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.sockPath, dialTimeout)
	if err != nil {
		return Response{}, fmt.Errorf("adminwire: dial %s: %w", c.sockPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return Response{}, err
	}
	// 写失败不立即返回, 先试着读一次响应.
	//
	// 服务端在 SO_PEERCRED 判定不通过时, 会在读请求之前就写出
	// CodeUnauthorized 并关连接 - 这是有意的 (不为未授权对端读取, 解析它的
	// 载荷). 于是客户端这一侧完全可能在写请求的过程中撞上 EPIPE: 连接已经
	// 被对端关掉了, 但那条拒绝响应其实已经在缓冲区里等着.
	//
	// 直接返回写错误的话, 运维看到的是"broken pipe"而不是"unauthorized",
	// 把一个明确的权限问题伪装成网络故障, 极其浪费排查时间.
	//
	// 读也失败时才把写错误报出去 - 那才是真正的连接问题.
	writeErr := WriteTo(conn, req)

	var resp Response
	if err := ReadFrom(conn, &resp); err != nil {
		if writeErr != nil {
			return Response{}, writeErr
		}
		return Response{}, fmt.Errorf("adminwire: read response: %w", err)
	}
	return resp, nil
}
