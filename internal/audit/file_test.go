package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRecorder 造一个写到临时目录的记录器，时钟固定。
func newTestRecorder(t *testing.T, maxBytes int64) (*FileRecorder, string) {
	t.Helper()
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	r, err := NewFileRecorder(FileConfig{
		Dir:      dir,
		MaxBytes: maxBytes,
		MaxFiles: 2,
		Log:      discardLog(),
		now:      func() time.Time { return at },
	})
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func recordN(r *FileRecorder, n int) {
	for i := 0; i < n; i++ {
		r.Record(context.Background(), Event{
			Action:  "test.Action",
			Subject: "pkg:com.example uid:20001",
			Detail:  "i",
		})
	}
}

func readCurrent(t *testing.T, dir string) []Record {
	t.Helper()
	records, skipped, err := ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("跳过了 %d 行解不开的记录", skipped)
	}
	return records
}

// 一条正常的链：序号连续、prev 相扣、哈希对得上。
func TestFileRecorder_ChainVerifies(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 5)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records := readCurrent(t, dir)
	// 首条是 ChainStarted：一条全新的链必须显式说明自己是从哪里开始的。
	if len(records) != 6 {
		t.Fatalf("记录数 = %d, want 6（ChainStarted + 5）", len(records))
	}
	if records[0].Action != actionChainStarted {
		t.Fatalf("首条 action = %q, want %q", records[0].Action, actionChainStarted)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("第 %d 条校验失败: %v", idx, err)
	}
}

// 【改一条的内容会被发现】。
//
// 这是本机制的核心用途：把 denied=true 改成 false、把 subject 换个包名，
// 都会让 hash 对不上。
func TestFileRecorder_DetectsModifiedRecord(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	r.Record(context.Background(), Event{Action: "a", Subject: "s", Denied: true})
	recordN(r, 2)
	_ = r.Close()

	records := readCurrent(t, dir)
	// records[0] 是 ChainStarted，被审计的那条在 [1]。
	// 把它的 denied 改掉、hash 不动——正是手改文件的样子。
	if records[1].Action != "a" {
		t.Fatalf("第二条 action = %q, want a", records[1].Action)
	}
	records[1].Denied = false

	idx, err := VerifyChain(records, "", 1)
	if err == nil {
		t.Fatal("被改过的记录通过了校验")
	}
	if idx != 1 {
		t.Fatalf("报告的位置 = %d, want 1", idx)
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("err = %v, want 哈希不符", err)
	}
}

// 【删掉中间几条会被发现】：序号跳跃。
func TestFileRecorder_DetectsDeletedRecords(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 5)
	_ = r.Close()

	records := readCurrent(t, dir)
	// 删掉中间两条。
	tampered := append([]Record{records[0]}, records[3:]...)

	idx, err := VerifyChain(tampered, "", 1)
	if err == nil {
		t.Fatal("删除记录后仍然通过了校验")
	}
	if idx != 1 {
		t.Fatalf("报告的位置 = %d, want 1（第一条对不上的）", idx)
	}
	if !strings.Contains(err.Error(), "removed or inserted") {
		t.Fatalf("err = %v, want 序号跳跃", err)
	}
}

// 【对调顺序会被发现】：prev 链接不上。
func TestFileRecorder_DetectsReordering(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 4)
	_ = r.Close()

	records := readCurrent(t, dir)
	records[1], records[2] = records[2], records[1]

	if _, err := VerifyChain(records, "", 1); err == nil {
		t.Fatal("对调顺序后仍然通过了校验")
	}
}

// 重启后链继续，不从 1 重新开始。
//
// 重置会让「进程重启」与「有人删了文件重建」在链上无法分辨。
func TestFileRecorder_ResumesChainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	newAt := func() *FileRecorder {
		r, err := NewFileRecorder(FileConfig{
			Dir: dir, MaxFiles: 2, Log: discardLog(),
			now: func() time.Time { return at },
		})
		if err != nil {
			t.Fatalf("NewFileRecorder: %v", err)
		}
		return r
	}

	first := newAt()
	recordN(first, 3)
	_ = first.Close()

	second := newAt()
	recordN(second, 2)
	_ = second.Close()

	records := readCurrent(t, dir)
	// ChainStarted + 3 + 2 = 6。【第二次启动不该再有 ChainStarted】。
	if len(records) != 6 {
		t.Fatalf("记录数 = %d, want 6（重启不该开新链）", len(records))
	}
	starts := 0
	for _, rec := range records {
		if rec.Action == actionChainStarted {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("ChainStarted 出现 %d 次，want 1——重启不该开新链", starts)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("跨重启的链在第 %d 条断了: %v", idx, err)
	}
	if records[5].Seq != 6 {
		t.Fatalf("末条 seq = %d, want 6", records[5].Seq)
	}
}

// 【文件被删掉重建时开新链，并显式记一条说明】。
//
// 悄悄从 seq=1 接着写，会让截断攻击看起来像一次正常重启。
func TestFileRecorder_MarksNewChainWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 3)
	_ = first.Close()

	// 模拟「有人清理了一下」。
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(second, 1)
	_ = second.Close()

	records := readCurrent(t, dir)
	if len(records) != 2 {
		t.Fatalf("记录数 = %d, want 2（ChainStarted + 1 条）", len(records))
	}
	if records[0].Action != actionChainStarted {
		t.Fatalf("首条 action = %q, want %q", records[0].Action, actionChainStarted)
	}
	if records[0].Detail == "" {
		t.Fatal("ChainStarted 没有说明原因")
	}
	// 【序号从 1 重来】。这正是它与「正常重启」的区别，而 ChainStarted
	// 这条记录是唯一能说清「为什么从 1 开始」的东西。
	if records[0].Seq != 1 || records[0].Prev != "" {
		t.Fatalf("新链首条 seq=%d prev=%q, want 1 与空", records[0].Seq, records[0].Prev)
	}
}

// 轮转之后新文件的第一条带着旧链的末尾哈希，链跨文件仍然连得上。
//
// 没有它，每次轮转在校验工具眼里都是一次「seq 从 1 重新开始」。
func TestFileRecorder_RotationCarriesChain(t *testing.T) {
	// 阈值设得很小，几条就触发轮转。
	r, dir := newTestRecorder(t, 400)
	recordN(r, 12)
	_ = r.Close()

	if _, statErr := os.Stat(filepath.Join(dir, FileName+".1")); statErr != nil {
		t.Fatalf("没有发生轮转——阈值没生效: %v", statErr)
	}
	current := readCurrent(t, dir)
	if len(current) == 0 {
		t.Fatal("轮转后当前文件是空的")
	}

	// 新文件的第一条是 Rotated，它携带旧链的末尾。
	if current[0].Action != actionRotated {
		t.Fatalf("新文件首条 action = %q, want %q", current[0].Action, actionRotated)
	}
	// 【序号跨文件继续，不从 1 重来】。重来的话，校验工具无法把它与
	// 「有人把文件删了重建」分开。
	if current[0].Seq <= 1 {
		t.Fatalf("轮转后 seq = %d，链没有跨文件延续", current[0].Seq)
	}
	if current[0].Prev == "" {
		t.Fatal("轮转后首条没有 prev——链断在了文件边界上")
	}
	// 当前文件自身是一段合法的链，接在 current[0].Prev 之后。
	if idx, err := VerifyChain(current, current[0].Prev, current[0].Seq); err != nil {
		t.Fatalf("当前文件第 %d 条校验失败: %v", idx, err)
	}
	// Detail 必须写明它接的是哪一条，否则跨文件校验只能靠猜。
	if !strings.Contains(current[0].Detail, "carried_hash=") {
		t.Fatalf("Rotated 记录没说明接的是哪条: %q", current[0].Detail)
	}
}

// truncateLastLine 砍掉文件最后一行的后半截，模拟断电时只落了半行。
//
// 【按行边界算而不是砍固定字节数】：记录长度会随字段变化，写死一个数字的
// 测试在改了任何一个字段之后就不再测它本来要测的东西。
func truncateLastLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := trimNewline(data)
	start := len(trimmed)
	for start > 0 && trimmed[start-1] != '\n' {
		start--
	}
	if start == 0 {
		t.Fatal("文件里只有一行，构造不出「末行残缺」")
	}
	// 保留最后一行的前半截：足以让它解不开，又不至于整行消失。
	keep := start + (len(trimmed)-start)/2
	if err := os.WriteFile(path, data[:keep], filePerm); err != nil {
		t.Fatal(err)
	}
}

// 末尾残缺的一行是崩溃现象，不是篡改：跳过它，其余照读。
func TestReadFile_TolerantOfTruncatedTail(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 3)
	_ = r.Close()

	path := filepath.Join(dir, FileName)
	truncateLastLine(t, path)

	records, skipped, err := ReadFile(path)
	if err != nil {
		t.Fatalf("残缺尾行不该让整个文件读失败: %v", err)
	}
	// ChainStarted + 3 条，砍掉末行残缺的那条 → 3 条完整的。
	if len(records) != 3 {
		t.Fatalf("记录数 = %d, want 3（末条残缺被跳过）", len(records))
	}
	// 【残片必须被报出来】：它意味着这台机器上发生过非正常停机。
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("第 %d 条校验失败: %v", idx, err)
	}
}

// 残缺尾行之后重启：链尾从最后一条【完整】记录恢复，不开新链。
func TestFileRecorder_ResumesAfterTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 3)
	_ = first.Close()

	path := filepath.Join(dir, FileName)
	truncateLastLine(t, path)

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(second, 1)
	_ = second.Close()

	records, skipped, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// 残片还在文件中间，仍然要被报出来。
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	// 【链没有断】：那条记录从来没被完整写入过，后面的接的是它之前那条。
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("崩溃残片不该让链断在第 %d 条: %v", idx, err)
	}
	starts := 0
	for _, rec := range records {
		if rec.Action == actionChainStarted {
			starts++
		}
	}
	// 只该有开头那一条。第二条意味着残缺尾行被误判成「文件不可读」。
	if starts != 1 {
		t.Fatalf("ChainStarted 出现 %d 次，want 1", starts)
	}
}

// 错误也进链：Denied 的原因是审计最要紧的内容之一。
func TestFileRecorder_CarriesError(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	r.Record(context.Background(), Event{
		Action:  "perm.Denied",
		Subject: "pkg:com.example",
		Denied:  true,
		Err:     errors.New("permission not granted"),
	})
	_ = r.Close()

	records := readCurrent(t, dir)
	if len(records) != 2 {
		t.Fatalf("记录数 = %d, want 2（ChainStarted + 1）", len(records))
	}
	if records[1].Err != "permission not granted" {
		t.Fatalf("err = %q", records[1].Err)
	}
	if !records[1].Denied {
		t.Fatal("denied 丢了")
	}
}

// 文件权限必须是 0600：审计里有 package id、uid、拒绝原因，
// 读者是运维，不是机器上的 App。
func TestFileRecorder_FileIsOwnerOnly(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 1)
	_ = r.Close()

	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Fatalf("权限 = %o, want %o", perm, filePerm)
	}
}
