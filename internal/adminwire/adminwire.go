// Package adminwire 是 nervud 特权管理通道（nervusctl <-> nervud）的线格式与客户端。
//
// 它刻意是一个叶子包：只依赖标准库与 net，不 import 任何 nervud 内核模块
// （pkgregistry/permission/authority...）。这样 cmd/nervusctl 能只链接这一小片
// 代码，而不是把整个内核 TCB 拖进 CLI 二进制。服务端（internal/admin）与客户端
// （cmd/nervusctl）共用本包的 Request/Response/编解码，保证两侧永不漂移。
//
// 这条通道不是 App 面向的跨语言控制面；后者只使用 nervus-ipc 的冻结 proto，
// 避免出现两个不兼容的 wire 真源。本通道是 nervud 与其同仓 Go 特权
// 运维工具之间的内部边界：单进程写者仍是 nervud，nervusctl 只是把命令投递过去。
// 因此这里用长度前缀 + JSON（对 Go <-> Go、低频、root-only 的运维面足够），不引入
// proto/method_id 那套跨语言机制。
//
// 帧格式：4 字节大端长度 N + N 字节 JSON。与 internal/ipc/frame.go 同布局，但本包
// 自持一份最小实现，不 import internal/ipc（那会把内核依赖拖进 CLI）。
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

// 管理命令标识。服务端按 Request.Cmd 分派；未知命令回 CodeBadRequest。
const (
	// CmdBeginStaging 请求 nervud 在其掌控的 staging 根下新建一个空目录，返回
	// 绝对路径。CLI 随后把 .nspkg 解包进去，再发 CmdInstall。由 nervud 建目录
	// （而非 CLI 自己在任意位置建）保证：位置与 PackageRoot 同一文件系统（安装
	// 期 renameat2 才能成功）、属主/权限受控、且 install 时的路径逃逸校验有明确
	// 的必须是我发出的目录判据。
	CmdBeginStaging = "begin-staging"
	// CmdInstall 触发对一个已 staging 目录的安装。签名/digest/裁决全部在 nervud
	// 的 pkgregistry 里复核 - CLI 不做任何安全判定。
	CmdInstall = "install"
	// CmdUninstall 卸载一个动态安装的 Package。
	CmdUninstall = "uninstall"
	// CmdList 列出当前已装 Package。
	CmdList = "list"
	// CmdSetEnabled 停用/启用一个 Component。
	CmdSetEnabled = "set-enabled"
	// CmdSetPermission 设置一个运行期（GrantUser）权限的授予状态（grant/revoke）。
	CmdSetPermission = "set-permission"
)

// 授予状态的 wire 表示。与 permission.GrantState 一一对应，但本包不 import
// permission（保持叶子包），映射由服务端完成。
const (
	GrantStateNotRequested    = "not-requested"
	GrantStateGranted         = "granted"
	GrantStateDenied          = "denied"
	GrantStateDeniedPermanent = "denied-permanent"
)

// 机器可读的结果码。CLI 据此决定退出码/措辞；Message 只作人类可读补充。
const (
	CodeOK           = "ok"
	CodeBadRequest   = "bad-request"  // 命令/参数不合法（含路径逃逸）
	CodeUnauthorized = "unauthorized" // 对端不是被许可的运维身份
	CodeNotFound     = "not-found"    // 目标 Package/Component 不存在
	CodeFailed       = "failed"       // 底层操作失败（安装裁决拒绝、IO 错误...）
)

// Request 是 CLI -> nervud 的一条命令。一条连接一条命令（发一个 Request、收一个
// Response、随即关闭），不做长连接状态机 - 运维面低频，简单胜过复用。
type Request struct {
	Cmd         string `json:"cmd"`
	StagingDir  string `json:"staging_dir,omitempty"`
	PackageID   string `json:"package_id,omitempty"`
	ComponentID string `json:"component_id,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	Permission  string `json:"permission,omitempty"`
	GrantState  string `json:"grant_state,omitempty"`
}

// Response 是 nervud -> CLI 的结果。OK=false 时 Code/Message 说明原因。
type Response struct {
	OK         bool          `json:"ok"`
	Code       string        `json:"code,omitempty"`
	Message    string        `json:"message,omitempty"`
	StagingDir string        `json:"staging_dir,omitempty"` // begin-staging 的产物
	Package    *PackageInfo  `json:"package,omitempty"`     // install 的产物
	Packages   []PackageInfo `json:"packages,omitempty"`    // list 的产物
}

// PackageInfo 是一个已装 Package 的对外投影（install 结果 / list 项）。
type PackageInfo struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	VersionCode uint64   `json:"version_code"`
	Trust       string   `json:"trust"`
	Source      string   `json:"source"`
	Granted     []string `json:"granted,omitempty"`  // 已授予权限（供人确认）
	Disabled    []string `json:"disabled,omitempty"` // 已停用 Component
}

// MaxMessageBytes 是单条 JSON 消息的硬上限。管理消息都很小（install 只带一个路径，
// list 结果与 Package 数成正比），1 MiB 远够，又能挡住畸形长度前缀。
const MaxMessageBytes = 1 << 20

const lengthPrefixBytes = 4

// ErrMessageTooLarge 长度前缀超过硬上限。
var ErrMessageTooLarge = errors.New("adminwire: message exceeds hard limit")

// WriteTo 把 v 编码为 JSON 并以4 字节长度 + 正文写出。服务端写 Response、
// 客户端写 Request 都走它。
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

// ReadFrom 读满一条4 字节长度 + 正文并解码进 v。服务端读 Request、客户端读
// Response 都走它。长度超限即报错（不为攻击者自称的正文分配缓冲）。
func ReadFrom(r io.Reader, v any) error {
	var hdr [lengthPrefixBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // 含 io.EOF：对端关闭
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

// DefaultSockPath 是 nervud 管理通道的固定路径。与 App 控制面
// （/run/nervus/nervud.sock）分开：那条面向 App（UID 落在 App 段），本条面向
// root/运维（0600），两套准入规则不混。
const DefaultSockPath = "/run/nervus/nervud-admin.sock"

// dialTimeout / ioTimeout 给 CLI 侧一条不会永久挂起的路径。管理命令都很快；
// 一旦 nervud 没响应，CLI 应尽快报错退出而不是卡住运维脚本。
const (
	dialTimeout = 5 * time.Second
	ioTimeout   = 30 * time.Second // install 触发的裁决/落盘可能稍慢，留足余量
)

// Client 是 nervusctl 侧的最小客户端。不常驻、不持有任何状态 - 每条命令一次
// Dial -> 写 -> 读 -> 关（真源永远是 nervud 进程内的 Registry，CLI 只投递）。
type Client struct {
	sockPath string
}

// NewClient 构造一个指向 sockPath 的客户端。
func NewClient(sockPath string) *Client {
	if sockPath == "" {
		sockPath = DefaultSockPath
	}
	return &Client{sockPath: sockPath}
}

// Do 执行一条命令：连、写 Request、读 Response、关。传输失败返回 error；
// 业务失败（OK=false）不作为 error 返回，交给调用方按 Response.Code 处理。
func (c *Client) Do(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.sockPath, dialTimeout)
	if err != nil {
		return Response{}, fmt.Errorf("adminwire: dial %s: %w", c.sockPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return Response{}, err
	}
	if err := WriteTo(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := ReadFrom(conn, &resp); err != nil {
		return Response{}, fmt.Errorf("adminwire: read response: %w", err)
	}
	return resp, nil
}
