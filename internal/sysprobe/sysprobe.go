// sysprobe 是叶子包：不 import 任何兄弟模块（ipc/identity 反过来 import 它）
// 依赖箭头永远指向 sysprobe，结构上不可能出现 import cycle
package sysprobe

import "errors"

// Ucred 是 UDS 对端的内核可信凭证，对应 Linux 的 struct ucred。
//
// 这三个值来自内核，不来自对端发来的任何字节 - 客户端无法伪造。
// 这是架构 sec 10.2 nervud 验证声明，而不是相信声明 的物理基础：客户端可以在
// Hello 里自报 Component ID，但那只是待核对的线索，UID 才是身份裁决的依据
//
// 字段类型跟随 Linux struct ucred（pid_t 有符号，uid_t/gid_t 无符号），不做
// 统一成 int 更好写的转换：UID 与 authority.Invariants.CheckUID 的 uint32
// 参数直接对齐，少一次类型转换就少一处符号错误的机会
type Ucred struct {
	PID int32
	UID uint32
	GID uint32
}

var ErrUnsupportedPlatform = errors.New("sysprobe: operation requires linux")
