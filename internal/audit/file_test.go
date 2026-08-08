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
	// 末条是 Closed：一次干净的收尾。
	if len(records) != 7 {
		t.Fatalf("记录数 = %d, want 7（ChainStarted + 5 + Closed）", len(records))
	}
	if records[0].Action != ActionChainStarted {
		t.Fatalf("首条 action = %q, want %q", records[0].Action, ActionChainStarted)
	}
	if last := records[len(records)-1]; last.Action != ActionClosed {
		t.Fatalf("末条 action = %q, want %q", last.Action, ActionClosed)
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
	// ChainStarted + 3 + Closed + 2 + Closed = 8。
	// 【第二次启动不该再有 ChainStarted】，也【不该有 UncleanShutdown】——
	// 上一段是 Close 收尾的，链尾就是 Closed。
	if len(records) != 8 {
		t.Fatalf("记录数 = %d, want 8（重启不该开新链）", len(records))
	}
	starts, unclean := 0, 0
	for _, rec := range records {
		switch rec.Action {
		case ActionChainStarted:
			starts++
		case ActionUncleanShutdown:
			unclean++
		}
	}
	if starts != 1 {
		t.Fatalf("ChainStarted 出现 %d 次，want 1——重启不该开新链", starts)
	}
	if unclean != 0 {
		t.Fatalf("干净停机后仍报了 %d 次 UncleanShutdown", unclean)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("跨重启的链在第 %d 条断了: %v", idx, err)
	}
	if last := records[len(records)-1]; last.Seq != 8 {
		t.Fatalf("末条 seq = %d, want 8", last.Seq)
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
	if len(records) != 3 {
		t.Fatalf("记录数 = %d, want 3（ChainStarted + 1 条 + Closed）", len(records))
	}
	if records[0].Action != ActionChainStarted {
		t.Fatalf("首条 action = %q, want %q", records[0].Action, ActionChainStarted)
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
	if current[0].Action != ActionRotated {
		t.Fatalf("新文件首条 action = %q, want %q", current[0].Action, ActionRotated)
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
	// ChainStarted + 3 条 + Closed，砍掉末行（Closed）→ 4 条完整的。
	if len(records) != 4 {
		t.Fatalf("记录数 = %d, want 4（末条残缺被跳过）", len(records))
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
		if rec.Action == ActionChainStarted {
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
	if len(records) != 3 {
		t.Fatalf("记录数 = %d, want 3（ChainStarted + 1 + Closed）", len(records))
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

// ---- 掉电持久性 -------------------------------------------------------------
//
// 这几条守的是三件事：正常停机有终结标记、非正常停机在链里【留得下名字】、
// 以及 fsync 真的被调到了（而不是只在注释里说要调）。
//
// 【为什么必须有标记】：掉电丢掉尾部若干条之后，剩下的链完全自洽——序号连续、
// prev 相扣、哈希全对。校验工具会报「通过」。那不是安全，是一个假的确定性。

// simulatePowerLoss 模拟掉电：正常停掉记录器，再把文件尾部的记录剥掉。
//
// 【不能只是"不调 Close"】：写 goroutine 是随进程一起没的，不调 Close 只会
// 让用例去竞争一个还活着的 goroutine，测不出任何东西。
//
// 剥掉尾部才是掉电的真实形态——若干条已经 Write 但还在页缓存里的记录随电一起
// 消失，其中包括本该收尾的 Closed。剥完之后【剩下的链完全自洽】，这正是本机制
// 要解决的问题：没有标记的话，校验工具会对这个残缺的文件报「通过」。
func simulatePowerLoss(t *testing.T, dir string, lose int) {
	t.Helper()
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	end := len(bytesTrimNewline(data))
	for i := 0; i < lose; i++ {
		start := end
		for start > 0 && data[start-1] != '\n' {
			start--
		}
		if start == 0 {
			t.Fatal("文件里的记录不够剥")
		}
		end = start
	}
	if err := os.WriteFile(path, data[:end], filePerm); err != nil {
		t.Fatal(err)
	}
}

func bytesTrimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func countAction(records []Record, action string) int {
	n := 0
	for _, rec := range records {
		if rec.Action == action {
			n++
		}
	}
	return n
}

// 干净停机写终结记录，而且它是【最后一条】。
func TestFileRecorder_CleanCloseWritesTerminator(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 2)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	records := readCurrent(t, dir)
	last := records[len(records)-1]
	if last.Action != ActionClosed {
		t.Fatalf("末条 action = %q, want %q", last.Action, ActionClosed)
	}
	// 终结记录也在链上——它跟别的记录一样可被校验，不是文件外的元数据。
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("第 %d 条校验失败: %v", idx, err)
	}
}

// 【非正常停机在下次启动时被标出来】。这是整套机制的落点。
func TestFileRecorder_MarksUncleanShutdown(t *testing.T) {
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
	// 掉电：Closed 和它前面那条一起没了。
	simulatePowerLoss(t, dir, 2)

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(second, 1)
	_ = second.Close()

	records := readCurrent(t, dir)
	if n := countAction(records, ActionUncleanShutdown); n != 1 {
		t.Fatalf("UncleanShutdown 出现 %d 次, want 1", n)
	}
	// 【不能顺手开新链】：链本身没坏，坏的只是「尾巴可能少了几条」。
	// 开新链会把一次掉电说成一次文件重建，那是两种完全不同的事故。
	if n := countAction(records, ActionChainStarted); n != 1 {
		t.Fatalf("ChainStarted 出现 %d 次, want 1——掉电不该开新链", n)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("掉电重启后链断在第 %d 条: %v", idx, err)
	}

	// 标记必须紧跟在断点之后，否则读的人分不清是哪一段可疑。
	for i, rec := range records {
		if rec.Action == ActionUncleanShutdown {
			if records[i-1].Action == ActionClosed {
				t.Fatal("标记打在了一次干净收尾之后")
			}
			if !rec.Denied {
				t.Fatal("UncleanShutdown 该是 Denied，便于只筛拒绝类事件时也能看到")
			}
			return
		}
	}
	t.Fatal("没找到 UncleanShutdown")
}

// 干净停机之后重启【不】报 UncleanShutdown——否则这个标记会天天出现，
// 很快就没人看了。
func TestFileRecorder_NoFalseUncleanAfterCleanClose(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	for i := 0; i < 3; i++ {
		r, err := NewFileRecorder(cfg)
		if err != nil {
			t.Fatal(err)
		}
		recordN(r, 1)
		_ = r.Close()
	}

	records := readCurrent(t, dir)
	if n := countAction(records, ActionUncleanShutdown); n != 0 {
		t.Fatalf("干净重启 3 次却报了 %d 次 UncleanShutdown", n)
	}
}

// 文件被删掉重建时只开新链，不叠加 UncleanShutdown——
// 一次事故只该有一个名字。
func TestFileRecorder_MissingFileIsNewChainNotUnclean(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 2)
	_ = first.Close()
	simulatePowerLoss(t, dir, 1)

	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()

	records := readCurrent(t, dir)
	if n := countAction(records, ActionChainStarted); n != 1 {
		t.Fatalf("ChainStarted 出现 %d 次, want 1", n)
	}
	if n := countAction(records, ActionUncleanShutdown); n != 0 {
		t.Fatalf("文件缺失已经由 ChainStarted 说明了，不该再报 %d 次 UncleanShutdown", n)
	}
}

// ---- fsync 的节流 -----------------------------------------------------------
//
// 时间由 cfg.now 注入，用例里不 sleep：「1 秒」这个阈值是被真正断言的，
// 而不是靠 sleep 撞运气。
//
// 断言打在 Stats() 上而不是内部的 dirty 标志：dirty 只由写 goroutine 触碰，
// 从测试 goroutine 读它是 data race，-race 会当场抓住。

// waitRecords 等到写 goroutine 落了至少 n 条。
func waitRecords(t *testing.T, r *FileRecorder, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := r.Stats(); got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	got, _ := r.Stats()
	t.Fatalf("等不到第 %d 条落盘，只落了 %d 条", n, got)
}

// newClockedRecorder 造一个时钟可推进的记录器。
func newClockedRecorder(t *testing.T) (*FileRecorder, *time.Time) {
	t.Helper()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	clock := &at
	r, err := NewFileRecorder(FileConfig{
		Dir: t.TempDir(), Log: discardLog(),
		now: func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, clock
}

// 拒绝类事件立刻落盘：越权尝试、签名不过、撤权，都不该等定时器。
func TestFileRecorder_DeniedSyncsImmediately(t *testing.T) {
	r, clock := newClockedRecorder(t)

	// open 时的 ChainStarted 已经写过一条；把时钟推过节流窗口，
	// 让下一条拒绝确定不受上一次 sync 影响。
	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	_, before := r.Stats()

	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 2)

	if _, after := r.Stats(); after != before+1 {
		t.Fatalf("fsync 次数 %d -> %d, want +1（拒绝类事件该立刻落盘）", before, after)
	}
}

// 【连续拒绝不该变成一串背靠背的 fsync】。
//
// 逐条 sync 会让写 goroutine 的排空速度掉到每秒几十条，突发时队列溢出、
// 丢记录——为了不丢反而丢。窗口内的第二条留给定时器兜底。
func TestFileRecorder_DeniedIsThrottled(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)

	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 2)
	_, afterFirst := r.Stats()

	// 时钟不动 = 仍在节流窗口内。
	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 3)

	if _, after := r.Stats(); after != afterFirst {
		t.Fatalf("窗口内第二条拒绝把 fsync 从 %d 推到了 %d，节流没生效", afterFirst, after)
	}
}

// 节流窗口过去之后，下一条拒绝重新立刻落盘。
func TestFileRecorder_ThrottleReopensAfterInterval(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 2)
	_, base := r.Stats()

	*clock = clock.Add(minSyncInterval)
	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 3)

	if _, after := r.Stats(); after != base+1 {
		t.Fatalf("过了窗口仍未 fsync：%d -> %d", base, after)
	}
}

// 普通记录不触发立刻 fsync——否则批量就白做了。
func TestFileRecorder_PlainRecordDoesNotSync(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	_, before := r.Stats()

	recordN(r, 3)
	waitRecords(t, r, 4)

	if _, after := r.Stats(); after != before {
		t.Fatalf("普通记录把 fsync 从 %d 推到了 %d", before, after)
	}
}

// 【停机无条件 fsync】，不受节流管：这是最后一次机会。
func TestFileRecorder_CloseSyncs(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	recordN(r, 2)
	waitRecords(t, r, 3)
	_, before := r.Stats()

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, after := r.Stats(); after <= before {
		t.Fatalf("Close 没有 fsync：%d -> %d", before, after)
	}
}

// 【轮转前无条件 fsync】。
//
// Close 不隐含 fsync：旧文件带着没落盘的尾巴变成 .1，掉电后那段就没了，
// 而它前面的链依然自洽——验证工具看不出少了东西。
func TestFileRecorder_RotationSyncs(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	r, err := NewFileRecorder(FileConfig{
		Dir: dir, MaxBytes: 400, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	waitRecords(t, r, 1)
	_, before := r.Stats()

	// 时钟不动：这些普通记录都不会触发 syncIfDue，所以之后计数的任何增长
	// 都只能来自轮转本身。
	recordN(r, 12)
	waitRecords(t, r, 13)

	if _, statErr := os.Stat(filepath.Join(dir, FileName+".1")); statErr != nil {
		t.Fatalf("没有发生轮转——阈值没生效: %v", statErr)
	}
	if _, after := r.Stats(); after <= before {
		t.Fatalf("轮转没有 fsync 旧文件：%d -> %d", before, after)
	}
}

// 空闲时一次 fsync 都不做。
//
// 【少了 dirty 判断，定时器会每秒唤醒一次存储设备】。机器人大部分时间不产生
// 审计事件，那就是纯粹的 SD 卡磨损和功耗，换不到任何持久性。
func TestFileRecorder_IdleDoesNotSync(t *testing.T) {
	r, _ := newClockedRecorder(t)

	waitRecords(t, r, 1)
	// 等定时器至少烧过两轮。
	time.Sleep(2*minSyncInterval + 200*time.Millisecond)
	_, first := r.Stats()

	time.Sleep(2*minSyncInterval + 200*time.Millisecond)
	if _, second := r.Stats(); second != first {
		t.Fatalf("空闲期 fsync 从 %d 涨到了 %d——dirty 判断没生效", first, second)
	}
}
