// 本文件是「把一个已分配的 App UID 登记进系统用户库」这个特权操作。
//
// # 为什么内核必须做这件事
//
// systemd 的 User= 即便给的是数字 UID，也要求它能被 NSS 解析成一个真实用户；
// 否则 spawn 在 step USER 失败，退出码 217/USER。而 pkgregistry 分配 UID 之后
// 从不登记它们——结果是在一个没有预建这些用户的系统上，【任何 Package 组件
// 都起不来】。
//
// # 为什么不能交给系统服务
//
// 死锁：systemd 起任何包组件都要求它的 UID 可解析，而系统服务本身就是一个包
// 组件。那个「负责建用户的服务」自己就起不来。这不是取舍，是 bootstrap 顺序
// 强制的结论。
//
// # 为什么直接写文件而不是调 useradd
//
//  1. 嵌入式镜像未必装 shadow-utils。依赖一个可能不存在的外部二进制，
//     失败形态是「组件起不来」而不是「构建时报错」，排查成本极高。
//  2. UID 永不回收（allocator 是单调高水位，见 scan.go），因此这里【只追加、
//     从不删改】。append-only 让直接操作文件安全得多——不需要重写整个文件，
//     也就没有「重写到一半崩了」这种把 /etc/passwd 写坏的可能。
//
// 仍然按 shadow-utils 的约定持 /etc/.pwd.lock 排他锁，与系统上其它用户管理
// 工具互斥。
package authority

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	passwdPath = "/etc/passwd"
	groupPath  = "/etc/group"
	// pwdLockPath 是 shadow-utils 约定的用户库锁文件。持它才能与系统上其它
	// 用户管理工具（useradd/usermod/vipw）互斥。
	pwdLockPath = "/etc/.pwd.lock"

	// appUserShell 让这些账号无法登录。它们只是 systemd 用来设 UID 的身份，
	// 不对应任何人。
	appUserShell = "/usr/sbin/nologin"
	// appUserHome 指向一个不存在的路径：包的私有数据目录不是 home，
	// 把它写成 home 会让任何按 $HOME 找配置的库误入沙箱可写区。
	appUserHome = "/nonexistent"
)

// ErrAppUserConflict 目标 UID 已被一个不属于 nervus 的用户占用。
var ErrAppUserConflict = errors.New("authority: app uid already taken by a foreign user")

// EnsureAppUserRequest 请求把一个已分配的 App UID 登记进系统用户库。
//
// 幂等：条目已存在（且是我们建的）时什么都不做。
type EnsureAppUserRequest struct {
	UID uint32
	GID uint32
	// Name 是账号名。调用方给出，本层只校验形状——名字进 /etc/passwd 的第一列，
	// 含冒号或换行就能伪造出额外条目。
	Name string
}

func (EnsureAppUserRequest) Kind() Kind { return KindEnsureAppUser }

func (r EnsureAppUserRequest) Detail() string {
	return fmt.Sprintf("%s uid=%d", r.Name, r.UID)
}

// Validate 校验不变量。
func (r EnsureAppUserRequest) Validate(inv *Invariants) error {
	if err := inv.CheckUID(r.UID); err != nil {
		return err
	}
	if err := inv.CheckUID(r.GID); err != nil {
		return err
	}
	if !validAppUserName(r.Name) {
		return fmt.Errorf("%w: invalid app user name %q", ErrInvariantViolated, r.Name)
	}
	return nil
}

// validAppUserName 报告 name 是否是安全的账号名。
//
// 【冒号与换行是致命的】：/etc/passwd 是冒号分隔、换行分条的。一个含换行的
// 名字能凭空造出一条 uid=0 的条目。长度上限 32 是 useradd 的惯例，也避免
// 一个超长名字把行撑爆。
func validAppUserName(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	// 必须带 nervus- 前缀：让这些账号在 /etc/passwd 里一眼可辨，也保证我们
	// 永远不会去动一个不属于自己的条目。
	if !strings.HasPrefix(name, "nervus-") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// AppUserName 给出一个 UID 对应的账号名。
//
// 用 UID 而不是 package_id 做后缀：package_id 是反写域名（com.example.app），
// 含点号且可能超过 32 字符，两者都不适合做账号名。UID 唯一、定长、且与
// /etc/passwd 的第三列天然对应，排查时一眼能对上。
func AppUserName(uid uint32) string {
	return "nervus-app-" + strconv.FormatUint(uint64(uid), 10)
}

// EnsureAppUser 把一个 App UID 登记进系统用户库。幂等。
func (g *Gate) EnsureAppUser(ctx context.Context, subj Subject, req EnsureAppUserRequest) error {
	_, err := do(ctx, g, subj, req, g.osEnsureAppUser)
	return err
}

// existingUIDName 在 path（passwd 或 group 格式）里查 uid，返回它的名字。
//
// 两种文件的前三列布局一致（name:passwd:id:...），因此可以共用解析。
func existingUIDName(path string, uid uint32) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, fmt.Errorf("authority: read %s: %w", path, err)
	}
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		if f[2] == want {
			return f[0], true, nil
		}
	}
	return "", false, nil
}

// appendLine 以 O_APPEND 追加一行。
//
// O_APPEND 让写入相对于文件末尾原子（单次 write 不超过 PIPE_BUF 时内核保证
// 不交错），配合外层的 flock，两道保证叠加。不重写整个文件——重写到一半崩了
// 就是一个写坏的 /etc/passwd，那是能让系统起不来的故障。
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("authority: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("authority: append to %s: %w", path, err)
	}
	return f.Sync()
}
