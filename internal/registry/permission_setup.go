//go:build linux

package registry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// oPath is O_PATH, which syscall does not define on every architecture.
// O_PATH 在部分架构的 syscall 包中没有定义，这里补上。
const oPath = 0x200000

// POSIX ACL extended attribute format, as understood by the kernel
// 内核使用的 POSIX ACL 扩展属性格式
const (
	xattrACLAccess  = "system.posix_acl_access"
	xattrACLDefault = "system.posix_acl_default"

	aclVersion = 2

	aclTagUserObj  uint16 = 0x01
	aclTagUser     uint16 = 0x02
	aclTagGroupObj uint16 = 0x04
	aclTagGroup    uint16 = 0x08
	aclTagMask     uint16 = 0x10
	aclTagOther    uint16 = 0x20

	aclUndefinedID = 0xFFFFFFFF

	sIfmt  = 0o170000
	sIflnk = 0o120000
	sIfdir = 0o040000

	// deviceSkipDirs are dynamic or world-writable /dev subtrees; granting a group there
	// would expose other processes' ptys and shared memory, or is pointless.
	// /dev 下动态生成或所有人可写的目录，不授权
	deviceSkipDirs = "/dev/pts,/dev/shm,/dev/mqueue,/dev/hugepages"
)

// skippedDeviceDirs is the parsed form of deviceSkipDirs
var skippedDeviceDirs = func() map[string]struct{} {
	m := map[string]struct{}{}
	for _, d := range strings.Split(deviceSkipDirs, ",") {
		m[d] = struct{}{}
	}
	return m
}()

type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// SetupPermissionGroups is called once at startup. It ensures the builtin permission
// groups exist in /etc/group and that every permission path carries exactly the ACL
// entries its declared permissions require. Devices plugged in later are handled by
// udev rules, which must use the same GIDs.
// 启动时调用一次：确保内置权限组存在于 /etc/group，并把每条权限路径的 ACL
// 修正为它声明的权限组集合。热插拔设备由 udev 规则处理，规则里要用同一批 GID。
func SetupPermissionGroups() error {
	if err := ensurePermissionGroups(); err != nil {
		return err
	}

	all, err := collectPermissionTargets()
	if err != nil {
		return err
	}

	var failed int
	for path := range all {
		if err := applyPermissionACL(path, all); err != nil {
			slog.Warn("apply permission acl failed", "path", path, "error", err)
			failed++
		}
	}
	slog.Info("permission groups ready",
		"paths", len(all), "failed", failed)
	return nil
}

// pathGrant is one group's access on one concrete path
// 某个组在一个具体路径上的访问权限
type pathGrant struct {
	gid   int32
	bits  permissionBits
	isDir bool // a directory also gets a default ACL so new files inherit it
}

// expandedGrant is one concrete path produced by expanding a pathRule.
// pathGrant is embedded so expandRule only fills in bits/isDir; the caller fills in gid.
// 展开一条路径规则得到的具体路径；pathGrant 内嵌，expandRule 只填 bits/isDir，gid 由调用方填
type expandedGrant struct {
	path string
	pathGrant
}

// collectPermissionTargets expands every builtin permission rule into concrete paths
// 把内置权限的路径规则展开成实际路径
func collectPermissionTargets() (map[string][]pathGrant, error) {
	all := make(map[string][]pathGrant)

	for _, perm := range builtinPermissions {
		if !perm.IsGroupControlled() {
			continue
		}
		for _, rule := range builtinPermissionPaths[perm.ID] {
			found, err := expandRule(rule)
			if err != nil {
				return nil, fmt.Errorf("expand %s %s: %w", perm.ID, rule.path, err)
			}
			for _, e := range found {
				// The GID belongs to the permission, not to the rule
				// GID 属于权限条目，展开时填入
				e.gid = perm.GID
				all[e.path] = append(all[e.path], e.pathGrant)
			}
		}
	}

	mergeGrants(all)
	return all, nil
}

// expandRule turns one pathRule into concrete paths
// 将一条路径规则展开成实际路径
func expandRule(rule pathRule) ([]expandedGrant, error) {
	switch rule.kind {
	case pathKernelDir:
		path := filepath.Clean(rule.path)
		if err := ensureKernelDir(path); err != nil {
			return nil, err
		}
		return []expandedGrant{{
			path:      path,
			pathGrant: pathGrant{bits: rule.bits, isDir: true},
		}}, nil

	case pathDeviceTree:
		var found []expandedGrant
		root := filepath.Clean(rule.path)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // a vanished device is not an error
			}
			if d.IsDir() {
				if _, skip := skippedDeviceDirs[path]; skip {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			switch info.Mode().Type() {
			case os.ModeCharDevice, os.ModeDevice:
				found = append(found, expandedGrant{
					path:      path,
					pathGrant: pathGrant{bits: rule.bits},
				})
			}
			return nil
		})
		return found, err

	default:
		matches, err := filepath.Glob(rule.path)
		if err != nil {
			return nil, err
		}
		found := make([]expandedGrant, 0, len(matches))
		for _, m := range matches {
			// Symlinks are never touched: setting ACLs through a link could reach
			// a file the permission was never meant to cover.
			// 不处理符号链接，避免通过链接改到无关文件
			info, err := os.Lstat(m)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			found = append(found, expandedGrant{
				path:      filepath.Clean(m),
				pathGrant: pathGrant{bits: rule.bits, isDir: info.IsDir()},
			})
		}
		return found, nil
	}
}

// ensureKernelDir creates a kernel-owned directory if it is missing.
// It is intentionally not accessible to others; the group is granted through ACL.
// 创建内核持有的目录；others 不可访问，组通过 ACL 授予
func ensureKernelDir(path string) error {
	if err := os.MkdirAll(path, 0o710); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o710); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// mergeGrants unions the access bits of identical (path, gid) pairs
// 合并同一路径上同一 GID 的多条授予
func mergeGrants(all map[string][]pathGrant) {
	for path, list := range all {
		merged := make(map[int32]*pathGrant, len(list))
		for _, g := range list {
			cur, exists := merged[g.gid]
			if !exists {
				cp := g
				merged[g.gid] = &cp
				continue
			}
			cur.bits |= g.bits
			cur.isDir = cur.isDir || g.isDir
		}

		out := make([]pathGrant, 0, len(merged))
		for _, g := range merged {
			out = append(out, *g)
		}
		all[path] = out
	}
}

// applyPermissionACL sets the access ACL, and for directories the default ACL,
// so files created later inside inherit the same groups.
// The desired entry set is the union of every grant on the path, plus the grants of any
// ancestor that is itself a target: an ancestor directory's default ACL would already
// be inherited, so listing it explicitly makes the result independent of both ACL
// inheritance and the order in which paths are processed.
// 设置访问 ACL，目录另外设置默认 ACL（使之后新建的文件继承同样的组）。
// 期望的条目集合是本路径上的全部授予，以及"自身也是授权目标的上级目录"上的授予——
// 上级目录的默认 ACL 本来就会继承下来，显式列出让结果既不依赖 ACL 继承，
// 也不依赖路径的处理顺序。
func applyPermissionACL(path string, all map[string][]pathGrant) error {
	fd, err := syscall.Open(path, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&sIfmt == sIflnk {
		return errors.New("symlink")
	}

	// /proc/self/fd/N refers to exactly the inode that was checked above
	// 通过 /proc/self/fd 操作刚才检查过的同一个文件
	fdPath := "/proc/self/fd/" + strconv.Itoa(fd)

	// Union the grants of this path and of ancestor targets
	// 合并本路径与上级目标目录的授予
	desired := make(map[uint32]uint16)
	addGrants := func(grants []pathGrant) {
		for _, g := range grants {
			if bits := g.bits & 7; bits > 0 {
				desired[uint32(g.gid)] |= uint16(bits)
			}
		}
	}
	addGrants(all[path])
	for parent := filepath.Dir(path); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		addGrants(all[parent])
	}

	if err := syncACL(fdPath, xattrACLAccess, func(cur []aclEntry) []aclEntry {
		return buildAccessACL(st.Mode, desired, cur)
	}); err != nil {
		return err
	}

	if st.Mode&sIfmt == sIfdir {
		if err := syncACL(fdPath, xattrACLDefault, func(cur []aclEntry) []aclEntry {
			return buildDefaultACL(desired)
		}); err != nil {
			return err
		}
	}
	return nil
}

// syncACL reads the current ACL, feeds it to build, and writes the result only when it
// differs, so a correct setup causes no writes on the next boot.
// 读取现有 ACL，交给 build 计算目标值，只有不一致时才写回
func syncACL(fdPath, attr string, build func(cur []aclEntry) []aclEntry) error {
	cur, err := readACL(fdPath, attr)
	if err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			return nil
		}
		return err
	}

	// No extended ACL yet: write the inherited entries plus what the permissions ask for
	// 还没有扩展 ACL：直接写入现有条目加权限要求
	if len(cur) == 0 {
		return writeACL(fdPath, attr, build(cur))
	}

	// Already extended: only rewrite when the desired entry set actually differs
	// 已有扩展 ACL：只有期望的条目集合确实不同时才重写
	want := build(cur)
	if bytes.Equal(encodeACL(cur), encodeACL(want)) {
		return nil
	}
	return writeACL(fdPath, attr, want)
}

// writeACL writes an ACL, tolerating filesystems without ACL support
// 写 ACL；文件系统不支持时不算错误
func writeACL(fdPath, attr string, acl []aclEntry) error {
	err := syscall.Setxattr(fdPath, attr, encodeACL(acl), 0)
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return nil
	}
	return err
}

// buildAccessACL builds the access ACL: the three base entries mirror the file mode,
// the mask is the union of the group entry and every granted group, so a 0600 file such as
// /dev/video0 still lets the granted groups in, and named entries that are no longer
// requested are dropped.
// 构造访问 ACL：属主/属组/其他三项沿用文件模式；mask 取属组和所有授予组的并集，
// 这样 0600 的文件（如 /dev/video0）也能让被授予的组进来；不再需要的命名条目删除。
func buildAccessACL(mode uint32, desired map[uint32]uint16, cur []aclEntry) []aclEntry {
	ownerPerm := uint16(mode>>6) & 7
	groupPerm := uint16(mode>>3) & 7
	otherPerm := uint16(mode) & 7

	// With an extended ACL the mode group bits are the mask, so the real group_obj entry
	// must be read from the existing ACL
	// 已有扩展 ACL 时 mode 的组权限位是 mask，真正的 group_obj 要从现有 ACL 里取
	for _, e := range cur {
		if e.tag == aclTagGroupObj {
			groupPerm = e.perm
			break
		}
	}

	mask := groupPerm
	for _, perm := range desired {
		mask |= perm
	}
	if len(desired) == 0 {
		// No named entries: the ACL is just the mode, no mask entry is written
		// 没有命名条目时只有三项，不写 mask
		return []aclEntry{
			{tag: aclTagUserObj, perm: ownerPerm, id: aclUndefinedID},
			{tag: aclTagGroupObj, perm: groupPerm, id: aclUndefinedID},
			{tag: aclTagOther, perm: otherPerm, id: aclUndefinedID},
		}
	}

	acl := []aclEntry{
		{tag: aclTagUserObj, perm: ownerPerm, id: aclUndefinedID},
		{tag: aclTagGroupObj, perm: groupPerm, id: aclUndefinedID},
	}
	for gid, perm := range desired {
		acl = append(acl, aclEntry{tag: aclTagGroup, perm: perm, id: gid})
	}
	acl = append(acl,
		aclEntry{tag: aclTagMask, perm: mask, id: aclUndefinedID},
		aclEntry{tag: aclTagOther, perm: otherPerm, id: aclUndefinedID},
	)
	return acl
}

// buildDefaultACL is the access ACL to inherit plus execute on directories
// 默认 ACL：在访问 ACL 基础上给目录补上 x 位
func buildDefaultACL(desired map[uint32]uint16) []aclEntry {
	inherited := make(map[uint32]uint16, len(desired))
	for gid, perm := range desired {
		inherited[gid] = perm | 1
	}

	acl := []aclEntry{
		{tag: aclTagUserObj, perm: 7, id: aclUndefinedID},
		{tag: aclTagGroupObj, perm: 7, id: aclUndefinedID},
	}
	for gid, perm := range inherited {
		acl = append(acl, aclEntry{tag: aclTagGroup, perm: perm, id: gid})
	}
	if len(inherited) > 0 {
		acl = append(acl, aclEntry{tag: aclTagMask, perm: 7, id: aclUndefinedID})
	}
	acl = append(acl, aclEntry{tag: aclTagOther, perm: 0, id: aclUndefinedID})
	return acl
}

// readACL reads a system.posix_acl_* attribute. A missing attribute yields an empty ACL;
// other errors, including ENOTSUP for filesystems without ACL support, are returned as is.
// 读取 ACL 扩展属性：属性不存在时返回空；其他错误（包括不支持 ACL 的 ENOTSUP）原样返回。
func readACL(path, attr string) ([]aclEntry, error) {
	size, err := syscall.Getxattr(path, attr, nil)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) {
			return nil, nil
		}
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	n, err := syscall.Getxattr(path, attr, buf)
	if err != nil {
		return nil, err
	}
	return decodeACL(buf[:n])
}

// encodeACL serialises entries in the order the kernel expects
// 按内核要求的顺序序列化条目
func encodeACL(acl []aclEntry) []byte {
	sorted := append([]aclEntry(nil), acl...)
	sortACLEntries(sorted)

	buf := make([]byte, 4+len(sorted)*8)
	binary.LittleEndian.PutUint32(buf[0:4], aclVersion)
	for i, e := range sorted {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(buf[off:off+2], e.tag)
		binary.LittleEndian.PutUint16(buf[off+2:off+4], e.perm&7)
		binary.LittleEndian.PutUint32(buf[off+4:off+8], e.id)
	}
	return buf
}

// decodeACL parses the kernel representation, ignoring malformed input
// 解析内核表示，格式不对的输入直接忽略
func decodeACL(buf []byte) ([]aclEntry, error) {
	if len(buf) < 4 || (len(buf)-4)%8 != 0 {
		return nil, errors.New("malformed acl")
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != aclVersion {
		return nil, errors.New("unsupported acl version")
	}
	entries := make([]aclEntry, 0, (len(buf)-4)/8)
	for off := 4; off+8 <= len(buf); off += 8 {
		entries = append(entries, aclEntry{
			tag:  binary.LittleEndian.Uint16(buf[off : off+2]),
			perm: binary.LittleEndian.Uint16(buf[off+2:off+4]) & 7,
			id:   binary.LittleEndian.Uint32(buf[off+4 : off+8]),
		})
	}
	return entries, nil
}

// sortACLEntries orders entries as user_obj, named users, group_obj, named groups, mask, other
// 条目顺序：属主、命名用户、属组、命名组、mask、其他
func sortACLEntries(entries []aclEntry) {
	rank := func(tag uint16) int {
		switch tag {
		case aclTagUserObj:
			return 0
		case aclTagUser:
			return 1
		case aclTagGroupObj:
			return 2
		case aclTagGroup:
			return 3
		case aclTagMask:
			return 4
		default:
			return 5
		}
	}
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0; j-- {
			a, b := entries[j-1], entries[j]
			if rank(a.tag) < rank(b.tag) || (rank(a.tag) == rank(b.tag) && a.id <= b.id) {
				break
			}
			entries[j-1], entries[j] = entries[j], entries[j-1]
		}
	}
}

// ensurePermissionGroups makes sure every builtin permission group is present in
// /etc/group with its expected GID and name. A conflicting name or GID is reported
// and skipped; the kernel keeps working, only the group name is affected.
// 确保每个内置权限组以预期的 GID 和组名存在于 /etc/group；
// 组名或 GID 冲突时只记录并跳过，不影响内核工作
func ensurePermissionGroups() error {
	current, err := readGroupFile("/etc/group")
	if err != nil {
		return err
	}

	var missing []struct {
		name string
		gid  int32
	}
	for _, g := range builtinPermissionGroups {
		if err := checkGroupConflict(current, g.name, g.gid); err != nil {
			slog.Warn("permission group conflict", "group", g.name, "gid", g.gid, "error", err)
			continue
		}
		if _, exists := current.byGID[g.gid]; !exists {
			missing = append(missing, g)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	for _, g := range missing {
		line := fmt.Sprintf("%s:x:%d:\n", g.name, g.gid)
		if err := appendLine("/etc/group", line); err != nil {
			return fmt.Errorf("update /etc/group: %w", err)
		}
		// Keep /etc/gshadow in step when the system uses one
		// 系统使用 /etc/gshadow 时一并维护
		if _, statErr := os.Stat("/etc/gshadow"); statErr == nil {
			shadowLine := fmt.Sprintf("%s:!::\n", g.name)
			if err := appendLine("/etc/gshadow", shadowLine); err != nil {
				slog.Warn("update /etc/gshadow failed", "group", g.name, "error", err)
			}
		}
		slog.Info("permission group added", "group", g.name, "gid", g.gid)
	}
	return nil
}

type groupFileIndex struct {
	byGID  map[int32]string
	byName map[string]int32
}

func readGroupFile(path string) (*groupFileIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &groupFileIndex{byGID: map[int32]string{}, byName: map[string]int32{}}, nil
		}
		return nil, err
	}

	idx := &groupFileIndex{byGID: map[int32]string{}, byName: map[string]int32{}}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		gid, err := strconv.ParseInt(fields[2], 10, 32)
		if err != nil {
			continue
		}
		idx.byName[fields[0]] = int32(gid)
		idx.byGID[int32(gid)] = fields[0]
	}
	return idx, nil
}

// checkGroupConflict reports a name or GID that is already taken by another group
// 检查组名或 GID 是否已被别的组占用
func checkGroupConflict(idx *groupFileIndex, name string, gid int32) error {
	if existingGID, ok := idx.byName[name]; ok && existingGID != gid {
		return fmt.Errorf("name already used by gid %d", existingGID)
	}
	if existingName, ok := idx.byGID[gid]; ok && existingName != name {
		return fmt.Errorf("gid already used by %q", existingName)
	}
	return nil
}

// appendLine appends one line, starting on a fresh line if the file lacks a trailing newline
// 追加一行；文件末尾没有换行时先补一个
func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, info.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			line = "\n" + line
		}
	}
	_, err = f.WriteString(line)
	return err
}
