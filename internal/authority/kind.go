// 本文件定义 Authority 的操作码（Kind）、发起者（Subject）与请求契约（Request）
// Gate 与四步流水线见 authority.go；不变量见 invariant.go
package authority

import "fmt"

// Kind 是特权操作的固定操作码，用于审计落盘与离线分析
//
// 数值一旦分配永不复用。审计日志会被长期留存，复用数值等于让历史记录改变含义
// 废弃的操作把常量标 Deprecated 并留在原位
type Kind uint16

const (
	// KindUnspecified 零值即无效，防止未初始化的请求被当成合法操作
	KindUnspecified Kind = 0

	KindPrepareAppIdentity     Kind = 1
	KindInstallVerifiedPackage Kind = 2
	KindCreatePrivateDataDir   Kind = 3
	KindStartSandboxedProcess  Kind = 4
	KindStopProcess            Kind = 5
	KindSetOwner               Kind = 6
	KindEnableFsVerity         Kind = 7
	KindReboot                 Kind = 8
)

func (k Kind) String() string {
	switch k {
	case KindPrepareAppIdentity:
		return "PrepareAppIdentity"
	case KindInstallVerifiedPackage:
		return "InstallVerifiedPackage"
	case KindCreatePrivateDataDir:
		return "CreatePrivateDataDirectory"
	case KindStartSandboxedProcess:
		return "StartSandboxedProcess"
	case KindStopProcess:
		return "StopProcess"
	case KindSetOwner:
		return "SetOwner"
	case KindEnableFsVerity:
		return "EnableFsVerity"
	case KindReboot:
		return "Reboot"
	default:
		return "Unspecified"
	}
}

// Subject 是特权请求的发起者，用于审计归因
//
// identity 模块尚未落地，Subject 暂由调用方填写；接入 SO_PEERCRED 后
// 改为由 identity 解析连接得到，禁止外部客户端自报身份
type Subject struct {
	PackageID string // 空字符串 = 内核自身
	UID       uint32
}

// SubjectKernel 返回表示 nervud 内核自身的 Subject
// 它不自动获得豁免：底层不变量照样检查、照样审计
func SubjectKernel() Subject { return Subject{} }

// String 生成审计用的归因字符串（audit.Event.Subject 字段）
func (s Subject) String() string {
	if s.PackageID == "" {
		return "kernel"
	}
	return fmt.Sprintf("pkg:%s uid:%d", s.PackageID, s.UID)
}

// Request 是所有特权请求的统一契约
//
// # Kind 用于审计归类；Validate 做与调用者无关的自检
//
// 可选扩展：请求类型若额外实现 interface{ Detail() string }，返回值会进入
// 审计记录的 Detail 字段（如目标路径）
type Request interface {
	Kind() Kind
	Validate(inv *Invariants) error
}
