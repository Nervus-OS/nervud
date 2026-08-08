//go:build linux

// 本文件实现 perm.storage.user 的运行期授予与撤销: 增删用户文档区目录上
// POSIX ACL 里某个 UID 的条目.
//
// # 为什么是 ACL 而不是重启进程
//
// 可写路径 (ReadWritePaths) 是 systemd 在 spawn 时烧进 mount namespace 的,
// 进程起来之后改不动. 因此"运行期授予"曾经只能靠把整个包停掉重起, 让新进程
// 拿到新的 namespace - 用户点一下开关, 正在用的应用就消失重来一次.
//
// ACL 不同: 它在 open(2) 时求值, 对已经在跑的进程立即生效, 撤销同样立即.
// 于是两道门可以按各自的时间尺度分开:
//
//	挂载门 (安装期, 静态): manifest 申请了 perm.storage.user 且安装期裁决通过
//	                       -> user-data 进 ReadWritePaths. 进程生命周期内不变
//	访问门 (运行期, 即时): 用户是否同意 -> ACL 里那条 u:<uid>:rwx 的增删
//
// 这也让 runtime.go 开头那句"我们独有, Android 没有的立即撤销能力"名副其实:
// 在此之前那个"立即"是靠杀进程做到的.
//
// # 目录模式必须是 01770
//
// ACL 只在 mode 位挡得住人的时候才有意义. 01777 的 other 位是 rwx, 任何拿到
// 挂载的包都能写, ACL 里写什么都不影响结果. 见 preflight 对 UserDataRoot 的
// 声明 - 那两处必须一起改, 否则本文件是空转.
//
// # 只动 access ACL, 不设 default ACL
//
// default ACL 会让新建的文件与子目录继承这些条目, 那等于让每个被授权的包都能
// 写别的包创建的文件 - 比今天 (创建者所有 + umask, 别人只读) 宽. 这次改的是
// "授予何时生效", 不该顺手改变共享语义, 因此只设 access ACL: 新建文件与子目录
// 的归属和模式与今天完全一致.
package authority

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

// POSIX ACL 的 xattr 名与二进制布局. 结构见 Linux 的
// include/uapi/linux/posix_acl_xattr.h:
//
//	header { __le32 a_version }
//	entry  { __le16 e_tag; __le16 e_perm; __le32 e_id }
//
// 字段是 __le*, 与主机字节序无关, 因此下面一律显式用 LittleEndian.
const (
	aclAccessXattr = "system.posix_acl_access"
	aclVersion     = 2

	aclHeaderSize = 4
	aclEntrySize  = 8
)

// ACL 条目的 tag. 数值由 uapi 固定, 不可改
const (
	aclTagUserObj  uint16 = 0x01
	aclTagUser     uint16 = 0x02
	aclTagGroupObj uint16 = 0x04
	aclTagGroup    uint16 = 0x08
	aclTagMask     uint16 = 0x10
	aclTagOther    uint16 = 0x20
)

// aclUndefinedID 是 USER_OBJ / GROUP_OBJ / MASK / OTHER 这类无主体条目的 id
const aclUndefinedID uint32 = 0xFFFFFFFF

// 权限位
const (
	aclPermX uint16 = 1
	aclPermW uint16 = 2
	aclPermR uint16 = 4

	aclPermRWX = aclPermR | aclPermW | aclPermX
)

// aclEntry 是一条解出来的 ACL 记录
type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// parseACL 解出一份 access ACL. 空输入即"没有 ACL", 返回 nil 而不是错误 -
// 那是绝大多数目录的常态
func parseACL(raw []byte) ([]aclEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) < aclHeaderSize || (len(raw)-aclHeaderSize)%aclEntrySize != 0 {
		return nil, fmt.Errorf("%w: acl blob has %d bytes", ErrInvariantViolated, len(raw))
	}
	if v := binary.LittleEndian.Uint32(raw[:aclHeaderSize]); v != aclVersion {
		return nil, fmt.Errorf("%w: acl version %d is not %d", ErrInvariantViolated, v, aclVersion)
	}
	n := (len(raw) - aclHeaderSize) / aclEntrySize
	out := make([]aclEntry, 0, n)
	for i := 0; i < n; i++ {
		b := raw[aclHeaderSize+i*aclEntrySize:]
		out = append(out, aclEntry{
			tag:  binary.LittleEndian.Uint16(b[0:2]),
			perm: binary.LittleEndian.Uint16(b[2:4]),
			id:   binary.LittleEndian.Uint32(b[4:8]),
		})
	}
	return out, nil
}

// marshalACL 按内核要求的顺序编码: USER_OBJ, USER..., GROUP_OBJ, GROUP...,
// MASK, OTHER; 同 tag 内按 id 升序. 顺序错了 setxattr 直接回 EINVAL
func marshalACL(entries []aclEntry) []byte {
	sorted := append([]aclEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].tag != sorted[j].tag {
			return sorted[i].tag < sorted[j].tag
		}
		return sorted[i].id < sorted[j].id
	})

	buf := make([]byte, aclHeaderSize+len(sorted)*aclEntrySize)
	binary.LittleEndian.PutUint32(buf[:aclHeaderSize], aclVersion)
	for i, e := range sorted {
		b := buf[aclHeaderSize+i*aclEntrySize:]
		binary.LittleEndian.PutUint16(b[0:2], e.tag)
		binary.LittleEndian.PutUint16(b[2:4], e.perm)
		binary.LittleEndian.PutUint32(b[4:8], e.id)
	}
	return buf
}

// baseACLFromMode 用目录当前的 mode 位合成三条必备条目.
//
// 目录还没有 ACL 时需要它: POSIX 要求 USER_OBJ / GROUP_OBJ / OTHER 三条各恰好
// 一条, 而在没有 ACL 的目录上这三条的取值就是 mode 位本身. 凭空写死会把目录的
// 属主权限改掉
func baseACLFromMode(mode uint32) []aclEntry {
	return []aclEntry{
		{tag: aclTagUserObj, perm: uint16((mode >> 6) & 7), id: aclUndefinedID},
		{tag: aclTagGroupObj, perm: uint16((mode >> 3) & 7), id: aclUndefinedID},
		{tag: aclTagOther, perm: uint16(mode & 7), id: aclUndefinedID},
	}
}

// withNamedUser 增删一条 named-user 条目, 并按结果维护 MASK.
//
// MASK 的语义是"named 条目与 GROUP_OBJ 的权限上限", 有任何 named 条目时它是
// 必备的; 缺了它 setxattr 回 EINVAL. 反过来, named 条目全部删光后要连 MASK
// 一起去掉, 否则留下一条会把 GROUP_OBJ 压到 mask 之下
func withNamedUser(entries []aclEntry, uid uint32, allow bool) []aclEntry {
	out := make([]aclEntry, 0, len(entries)+2)
	for _, e := range entries {
		// 先摘掉目标 uid 与 MASK, 后面按需重建
		if e.tag == aclTagUser && e.id == uid {
			continue
		}
		if e.tag == aclTagMask {
			continue
		}
		out = append(out, e)
	}
	if allow {
		out = append(out, aclEntry{tag: aclTagUser, perm: aclPermRWX, id: uid})
	}

	// 还有 named 条目就必须补 MASK. 取 rwx: mask 是上限而非授予,
	// 压低它会连带削掉 GROUP_OBJ, 那是本操作不该有的副作用
	for _, e := range out {
		if e.tag == aclTagUser || e.tag == aclTagGroup {
			return append(out, aclEntry{tag: aclTagMask, perm: aclPermRWX, id: aclUndefinedID})
		}
	}
	return out
}

// hasNamedEntry 报告这份 ACL 里是否还有 named user/group 条目
func hasNamedEntry(entries []aclEntry) bool {
	for _, e := range entries {
		if e.tag == aclTagUser || e.tag == aclTagGroup {
			return true
		}
	}
	return false
}

// osSetUserDataAccess 是 SetUserDataAccess 的 Linux 实现.
//
// 读改写: 先取现有 ACL (没有就用 mode 位合成基线), 增删目标 UID, 再写回.
// 全量覆盖而不是增量 - POSIX ACL 的 xattr 本来就只能整份替换
func (g *Gate) osSetUserDataAccess(_ context.Context, req SetUserDataAccessRequest) (struct{}, error) {
	path := g.inv.UserDataRoot

	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return struct{}{}, fmt.Errorf("stat %s: %w", path, err)
	}
	// 不跟随符号链接: 用户文档区是 preflight 保证的真目录, 走到 symlink 说明
	// 这块地被人换过, 此时改 ACL 等于改到别处去
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return struct{}{}, fmt.Errorf("%w: %s is not a directory", ErrInvariantViolated, path)
	}

	raw, err := getxattrAll(path, aclAccessXattr)
	if err != nil {
		return struct{}{}, err
	}
	current, err := parseACL(raw)
	if err != nil {
		return struct{}{}, err
	}
	if len(current) == 0 {
		current = baseACLFromMode(st.Mode & 0o777)
	}

	next := withNamedUser(current, req.UID, req.Allowed)

	// named 条目全没了就把 xattr 整个删掉, 回到纯 mode 位的状态.
	// 留一份"只剩三条基线"的 ACL 在那里不是错, 但它会让 getfacl 的输出
	// 与没授权过的机器不一致, 排查时多一个需要解释的差异
	if !hasNamedEntry(next) {
		if rerr := unix.Removexattr(path, aclAccessXattr); rerr != nil &&
			!errors.Is(rerr, unix.ENODATA) && !errors.Is(rerr, unix.ENOTSUP) {
			return struct{}{}, fmt.Errorf("removexattr %s: %w", path, rerr)
		}
		return struct{}{}, nil
	}

	if serr := unix.Setxattr(path, aclAccessXattr, marshalACL(next), 0); serr != nil {
		return struct{}{}, fmt.Errorf("setxattr %s: %w", path, serr)
	}
	return struct{}{}, nil
}

// osReconcileUserDataAccess 是 ReconcileUserDataAccess 的 Linux 实现: 把 ACL 里
// 的 named-user 条目整体替换成给定集合.
//
// 存在的理由是 ACL 与授予状态可能漂移. 授予状态在 _grants.json, ACL 在文件
// 系统上, 两者各自持久化 - nervud 没在跑的时候卸载一个包, 它的授予记录被清掉
// 而 ACL 条目留在原地; UID 之后被新包复用, 那个新包就白拿到了用户文档区的
// 写权限, 没有任何界面显示过它.
//
// 于是把不变量定成【ACL 是授予状态的投影】: 启动时全量对账一次, 之后由
// ProjectRuntimePermission 增量维持. 全量替换而非逐条比对 - 前者天然幂等,
// 也顺手清掉任何来路不明的条目
func (g *Gate) osReconcileUserDataAccess(_ context.Context, req ReconcileUserDataAccessRequest) (struct{}, error) {
	path := g.inv.UserDataRoot

	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return struct{}{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return struct{}{}, fmt.Errorf("%w: %s is not a directory", ErrInvariantViolated, path)
	}

	raw, err := getxattrAll(path, aclAccessXattr)
	if err != nil {
		return struct{}{}, err
	}
	current, err := parseACL(raw)
	if err != nil {
		return struct{}{}, err
	}
	if len(current) == 0 {
		current = baseACLFromMode(st.Mode & 0o777)
	}

	// 只留三条基线, named 条目全部丢弃后按给定集合重建
	next := make([]aclEntry, 0, len(req.UIDs)+4)
	for _, e := range current {
		if e.tag == aclTagUser || e.tag == aclTagGroup || e.tag == aclTagMask {
			continue
		}
		next = append(next, e)
	}
	seen := make(map[uint32]struct{}, len(req.UIDs))
	for _, uid := range req.UIDs {
		if _, dup := seen[uid]; dup {
			continue
		}
		seen[uid] = struct{}{}
		next = append(next, aclEntry{tag: aclTagUser, perm: aclPermRWX, id: uid})
	}

	if !hasNamedEntry(next) {
		if rerr := unix.Removexattr(path, aclAccessXattr); rerr != nil &&
			!errors.Is(rerr, unix.ENODATA) && !errors.Is(rerr, unix.ENOTSUP) {
			return struct{}{}, fmt.Errorf("removexattr %s: %w", path, rerr)
		}
		return struct{}{}, nil
	}
	next = append(next, aclEntry{tag: aclTagMask, perm: aclPermRWX, id: aclUndefinedID})

	if serr := unix.Setxattr(path, aclAccessXattr, marshalACL(next), 0); serr != nil {
		return struct{}{}, fmt.Errorf("setxattr %s: %w", path, serr)
	}
	return struct{}{}, nil
}

// getxattrAll 读一个 xattr 的完整值. 属性不存在返回 nil - 对 ACL 而言
// "还没有" 是常态而不是错误
func getxattrAll(path, attr string) ([]byte, error) {
	size, err := unix.Getxattr(path, attr, nil)
	if err != nil {
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			return nil, nil
		}
		return nil, fmt.Errorf("getxattr %s %s: %w", path, attr, err)
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(path, attr, buf)
	if err != nil {
		if errors.Is(err, unix.ENODATA) {
			return nil, nil
		}
		return nil, fmt.Errorf("getxattr %s %s: %w", path, attr, err)
	}
	return buf[:n], nil
}
