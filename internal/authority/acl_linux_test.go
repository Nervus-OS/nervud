//go:build linux

package authority

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func newACLGate(t *testing.T, userDataRoot string) *Gate {
	t.Helper()
	g, err := New(Config{
		Auditor: &fakeRecorder{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Invariants: &Invariants{
			DataRoot:     userDataRoot,
			PackageRoot:  userDataRoot,
			UserDataRoot: userDataRoot,
			MinAppUID:    20000,
			MaxAppUID:    59999,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// 编码顺序错了 setxattr 直接回 EINVAL, 而那个错误不会说是顺序问题.
// 内核要求 USER_OBJ, USER..., GROUP_OBJ, GROUP..., MASK, OTHER
func TestMarshalACLOrdersEntriesForKernel(t *testing.T) {
	unsorted := []aclEntry{
		{tag: aclTagOther, perm: 0, id: aclUndefinedID},
		{tag: aclTagUser, perm: aclPermRWX, id: 20005},
		{tag: aclTagMask, perm: aclPermRWX, id: aclUndefinedID},
		{tag: aclTagUser, perm: aclPermRWX, id: 20001},
		{tag: aclTagUserObj, perm: aclPermRWX, id: aclUndefinedID},
		{tag: aclTagGroupObj, perm: aclPermRWX, id: aclUndefinedID},
	}

	round, err := parseACL(marshalACL(unsorted))
	if err != nil {
		t.Fatalf("parseACL: %v", err)
	}
	want := []aclEntry{
		{tag: aclTagUserObj, perm: aclPermRWX, id: aclUndefinedID},
		{tag: aclTagUser, perm: aclPermRWX, id: 20001},
		{tag: aclTagUser, perm: aclPermRWX, id: 20005},
		{tag: aclTagGroupObj, perm: aclPermRWX, id: aclUndefinedID},
		{tag: aclTagMask, perm: aclPermRWX, id: aclUndefinedID},
		{tag: aclTagOther, perm: 0, id: aclUndefinedID},
	}
	if len(round) != len(want) {
		t.Fatalf("条目数 = %d, want %d", len(round), len(want))
	}
	for i := range want {
		if round[i] != want[i] {
			t.Errorf("第 %d 条 = %+v, want %+v", i, round[i], want[i])
		}
	}
}

// 空输入是"这个目录还没有 ACL", 是常态而不是错误
func TestParseACLTreatsAbsentAsEmpty(t *testing.T) {
	entries, err := parseACL(nil)
	if err != nil || entries != nil {
		t.Fatalf("parseACL(nil) = %v, %v; want nil, nil", entries, err)
	}
	if _, err := parseACL([]byte{1, 2, 3}); err == nil {
		t.Error("长度不合法的 blob 被接受了")
	}
}

// 基线三条必须来自目录当前的 mode 位. 凭空写死会把属主权限一起改掉
func TestBaseACLFromModeMirrorsPermissionBits(t *testing.T) {
	got := baseACLFromMode(0o750)
	want := []aclEntry{
		{tag: aclTagUserObj, perm: aclPermRWX, id: aclUndefinedID},
		{tag: aclTagGroupObj, perm: aclPermR | aclPermX, id: aclUndefinedID},
		{tag: aclTagOther, perm: 0, id: aclUndefinedID},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条 = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// 有 named 条目就必须有 MASK (否则 setxattr 回 EINVAL); named 条目删光后
// MASK 也要一起消失, 留着会把 GROUP_OBJ 压到 mask 之下
func TestWithNamedUserMaintainsMask(t *testing.T) {
	base := baseACLFromMode(0o770)

	granted := withNamedUser(base, 20000, true)
	if !hasNamedEntry(granted) {
		t.Fatal("授予后没有 named 条目")
	}
	var maskCount int
	for _, e := range granted {
		if e.tag == aclTagMask {
			maskCount++
		}
	}
	if maskCount != 1 {
		t.Errorf("授予后 MASK 条目数 = %d, want 1", maskCount)
	}

	revoked := withNamedUser(granted, 20000, false)
	if hasNamedEntry(revoked) {
		t.Error("撤销后仍有 named 条目")
	}
	for _, e := range revoked {
		if e.tag == aclTagMask {
			t.Error("named 条目已删光, MASK 却还留着")
		}
	}

	// 重复授予不该堆出两条同 uid 的记录
	twice := withNamedUser(withNamedUser(base, 20000, true), 20000, true)
	var named int
	for _, e := range twice {
		if e.tag == aclTagUser && e.id == 20000 {
			named++
		}
	}
	if named != 1 {
		t.Errorf("重复授予后同 uid 条目数 = %d, want 1", named)
	}
}

// 走真内核: 本文件的二进制布局是照 uapi 手写的, 只有让内核收下并读回来
// 才算证明它对. 文件系统不支持 ACL 时跳过而不是失败 - 那是环境差异
func TestSetUserDataAccessAgainstKernel(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o1770); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	g := newACLGate(t, root)
	ctx := context.Background()

	if err := g.SetUserDataAccess(ctx, SubjectKernel(),
		SetUserDataAccessRequest{UID: 20000, Allowed: true}); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("文件系统不支持 POSIX ACL: %v", err)
		}
		t.Fatalf("授予: %v", err)
	}

	raw, err := getxattrAll(root, aclAccessXattr)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	entries, err := parseACL(raw)
	if err != nil {
		t.Fatalf("解析回读结果: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.tag == aclTagUser && e.id == 20000 && e.perm == aclPermRWX {
			found = true
		}
	}
	if !found {
		t.Fatalf("内核收下的 ACL 里没有 u:20000:rwx: %+v", entries)
	}

	// 撤销后 xattr 应当整个消失, 回到纯 mode 位
	if err := g.SetUserDataAccess(ctx, SubjectKernel(),
		SetUserDataAccessRequest{UID: 20000, Allowed: false}); err != nil {
		t.Fatalf("撤销: %v", err)
	}
	raw, err = getxattrAll(root, aclAccessXattr)
	if err != nil {
		t.Fatalf("撤销后回读: %v", err)
	}
	if len(raw) != 0 {
		t.Errorf("撤销后 ACL 仍在: %d 字节", len(raw))
	}
}

// UID 段位检查不能绕过: 把 root 或发行版服务写进用户文档区的 ACL 之后,
// 没有任何东西会再把那条记录摘掉
func TestSetUserDataAccessRejectsNonAppUID(t *testing.T) {
	g := newACLGate(t, t.TempDir())
	for _, uid := range []uint32{0, 1, 19999, 60000} {
		err := g.SetUserDataAccess(context.Background(), SubjectKernel(),
			SetUserDataAccessRequest{UID: uid, Allowed: true})
		if !errors.Is(err, ErrInvariantViolated) {
			t.Errorf("uid %d 被接受了: %v", uid, err)
		}
	}
}
