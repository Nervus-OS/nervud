// 本文件是 append-only 的审计文件记录器: 一条一行 JSON, 串成哈希链 (chain.go).
//
// # 为什么审计不能只写 slog
//
// 三条, 每条都能让审计在真正需要它的那一刻不可用:
//
//  1. 日志级别能把它过滤掉. 审计不是调试信息.
//  2. 它与普通日志混在一起, 量大时被轮转策略覆盖, 而覆盖的通常正是最早的那些
//
// - 事件的开头.
//  3. 没有任何东西阻止后来的写入覆盖它, 也没有任何东西能证明它没被覆盖过.
//
// 但 slog 仍然照写. 两条路各管一头: 文件负责可验证与留存, slog 负责
// "运维 journalctl 一看就见". 丢掉后者会让排查变难, 而那是审计的日常用途.
//
// # 落盘失败怎么办
//
// 审计是安全控制, 静默丢弃等于让它形同虚设; 但让机器人因为磁盘满而停机同样
// 不可接受. 取舍是让缺口可见: 写失败时计数, 恢复后立刻落一条
// audit.ChainGap 说明丢了多少. 链上会因此出现一次序号跳跃 - 而那正是想要的,
// 它与"有人删了记录"在校验工具眼里是同一种异常, 都必须被人看到.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultDir 是生产镜像的审计目录. 由 preflight 建好并设成 0700.
	DefaultDir = "/var/lib/nervus/audit"

	// FileName 是当前审计文件名. 轮转后的历史文件加.1.2 后缀.
	FileName = "audit.jsonl"

	// filePerm 是 0600: 审计里有 package id, uid, 拒绝原因.
	// 不给 group 与 other 任何位 - 审计的读者是运维, 不是机器上的 App.
	filePerm os.FileMode = 0o600
	dirPerm  os.FileMode = 0o700

	// ActionChainStarted 标记一条新链的起点.
	//
	// 必须显式记一条: 没有它的话, "进程重启"与"有人把文件删了重建"
	// 在链上长得一模一样 - 都是 seq 从 1 开始.
	ActionChainStarted = "audit.ChainStarted"

	// ActionChainGap 标记一段因写失败而丢失的记录.
	ActionChainGap = "audit.ChainGap"

	// ActionRotated 标记一次轮转. 它带着上一个文件的末尾哈希,
	// 让跨文件的链仍然连得上 - 否则每次轮转都像一次截断.
	ActionRotated = "audit.Rotated"

	// ActionClosed 是干净停机的终结记录, 写完它才 sync 并关文件.
	//
	// 它的作用不在自己, 在于它的缺席: 下次启动看到链尾不是它, 就知道上次
	// 是掉电或被 KILL 的, 那个位置可能少了最多 minSyncInterval 的记录.
	ActionClosed = "audit.Closed"

	// ActionUncleanShutdown 在启动时补记, 标出上一段的结尾不可信.
	ActionUncleanShutdown = "audit.UncleanShutdown"
)

// minSyncInterval 是两次 fsync 之间的最小间隔, 也是掉电丢失窗口的上界.
//
// # 为什么不是每条都 sync
//
// 写与 fsync 都在写 goroutine 上, 调用方入队即返回, 所以 fsync 不会拖慢任何
// 业务路径. 但它会拖慢写 goroutine 自己: SD 卡上一次 fsync 是几到几十毫秒,
// 逐条 sync 会让排空速度掉到每秒几十条, 突发时队列积压, 溢出, 丢记录 -
// 为了不丢反而丢, 方向正好反了.
//
// # 为什么是 1 秒
//
// 批量之后一次 fsync 覆盖这一秒里的全部记录, 写放大按条数摊薄. 代价是掉电最多
// 丢 1 秒, 而那 1 秒会被下次启动的 UncleanShutdown 标出来 - 窗口是已知的,
// 不是隐形的. 这跟 journald 的 SyncIntervalSec 是同一套取舍.
const minSyncInterval = time.Second

// FileConfig 是文件记录器的构造参数.
type FileConfig struct {
	// Dir 是审计目录, 如 /var/lib/nervus/audit.
	Dir string

	// MaxBytes 是单个文件的轮转阈值. <= 0 取 DefaultMaxBytes.
	MaxBytes int64

	// MaxFiles 是保留的历史文件数 (不含当前文件). <= 0 取 DefaultMaxFiles.
	MaxFiles int

	// QueueDepth 是异步队列深度. <= 0 取 DefaultQueueDepth.
	QueueDepth int

	// Log 是镜像输出, 也用于报告记录器自身的故障. 必填.
	Log *slog.Logger

	// now 供测试注入. 生产恒为 time.Now.
	now func() time.Time
}

const (
	// DefaultMaxBytes 16 MiB: 机器人上审计是低频事件, 这个大小够存很久,
	// 而单文件太大会让校验工具一次读进内存变得吃力.
	DefaultMaxBytes = 16 << 20
	// DefaultMaxFiles 保留 4 个历史文件, 连同当前的共 5 x 16 MiB = 80 MiB 上限.
	DefaultMaxFiles = 4
	// DefaultQueueDepth 与日志的 512 同数量级: 足以吸收突发, 又不至于在
	// 队列里囤积太多还没落盘的安全事件.
	DefaultQueueDepth = 512
)

// FileRecorder 把审计写成 append-only 的哈希链文件.
type FileRecorder struct {
	dir      string
	maxBytes int64
	maxFiles int
	log      *slog.Logger
	now      func() time.Time

	queue chan Event
	done  chan struct{}
	stop  chan struct{}
	once  sync.Once

	// dropped 是入队失败 (队列满) 的累计条数, 由写 goroutine 在下一次成功
	// 落盘时转成一条 ChainGap.
	dropped atomic.Uint64

	// written / synced 是累计写入条数与累计 fsync 次数.
	//
	// 两者的比值就是批量的实际效果: 写 1000 条只 fsync 了 20 次, 说明节流在
	// 起作用; 如果两者接近, 说明几乎每条都是 Denied, 该去看是什么在被反复拒绝.
	// 停机时记一笔, 也让测试能在不碰写 goroutine 私有状态的前提下断言时序.
	written atomic.Uint64
	synced  atomic.Uint64

	// 下面这些只由写 goroutine 触碰, 不加锁.
	file    *os.File
	size    int64
	seq     uint64
	prev    string
	pending uint64 // 已确认丢失, 还没记进 ChainGap 的条数

	// dirty 表示有已写入但还没 fsync 的记录.
	//
	// 它让空闲期一次 fsync 都不做. 少了这个判断, 定时器会每秒无条件唤醒
	// 一次存储设备 - 机器人大部分时间不产生审计事件, 那就是纯粹的 SD 卡磨损
	// 和功耗, 换不到任何持久性.
	dirty    bool
	lastSync time.Time
}

// NewFileRecorder 打开 (或新建) 审计文件并起写 goroutine.
//
// 打开失败是硬错误: 一个跑着但不记审计的系统, 比一个起不来的系统更糟 -
// 前者会让人以为有审计. 调用方应当让它冒泡到启动失败.
func NewFileRecorder(cfg FileConfig) (*FileRecorder, error) {
	if cfg.Log == nil {
		return nil, errors.New("audit: FileConfig.Log is required")
	}
	if cfg.Dir == "" {
		return nil, errors.New("audit: FileConfig.Dir is required")
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}
	if cfg.QueueDepth <= 0 {
		cfg.QueueDepth = DefaultQueueDepth
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}

	if err := os.MkdirAll(cfg.Dir, dirPerm); err != nil {
		return nil, fmt.Errorf("audit: create %s: %w", cfg.Dir, err)
	}

	r := &FileRecorder{
		dir:      cfg.Dir,
		maxBytes: cfg.MaxBytes,
		maxFiles: cfg.MaxFiles,
		log:      cfg.Log,
		now:      cfg.now,
		queue:    make(chan Event, cfg.QueueDepth),
		done:     make(chan struct{}),
		stop:     make(chan struct{}),
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	go r.run()
	return r, nil
}

// open 打开当前文件并恢复链尾.
func (r *FileRecorder) open() error {
	path := filepath.Join(r.dir, FileName)
	// O_APPEND: 每次写都原子地追加到末尾, 即使有别的进程也在写也不会互相覆盖.
	// 不给 O_TRUNC - 那正是要防的事.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, filePerm)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: stat %s: %w", path, err)
	}
	r.file = f
	r.size = info.Size()

	// 末行残缺时先补一个换行.
	//
	// O_APPEND 是从文件末尾接着写的. 上一次断电若只落了半行, 不补换行的话
	// 新记录会被直接粘在那截残片后面 - 于是一次崩溃毁掉的不是一条记录,
	// 而是两条: 残缺的那条, 和本该完好的下一条.
	if err := r.terminateDanglingLine(path); err != nil {
		_ = f.Close()
		r.file = nil
		return err
	}

	last, reason := lastLink(path)
	r.seq = last.Seq
	r.prev = last.Hash
	switch {
	case reason != "":
		// 读不出链尾时开新链, 并显式说明原因. 悄悄从 seq=1 接着写, 会让
		// "文件是新建的"与"文件被截断过"变得无法分辨.
		r.seq = 0
		r.prev = ""
		r.writeRecord(Event{
			Action:  ActionChainStarted,
			Subject: "kernel",
			Detail:  reason,
		})

	case last.Action != ActionClosed:
		// 上一段没有干净收尾: 掉电, 被 KILL, 或进程崩了.
		//
		// 链本身仍然连得上 - 正因为如此, 少掉的那几条看不出来. 这条记录
		// 就是那个缺口的名字: 它把"可能少了最多 1 秒的记录"写进链里, 让
		// 校验工具能报出来, 而不是给出一个假的"全部通过".
		//
		// Denied=true 是有意的: 它要在停机时立刻落盘, 同时也让只筛拒绝类
		// 事件的运维查询能看到它.
		r.writeRecord(Event{
			Action:  ActionUncleanShutdown,
			Subject: "kernel",
			Denied:  true,
			Detail: fmt.Sprintf(
				"last_seq=%d last_action=%s window<=%s",
				last.Seq, last.Action, minSyncInterval),
		})
	}
	return nil
}

// terminateDanglingLine 在文件不以换行结尾时补一个.
//
// 补完之后残片自成一行: ReadFile 与 lastLink 都会把它当成解不开的一行跳过,
// 而不影响它前后的任何记录.
func (r *FileRecorder) terminateDanglingLine(path string) error {
	if r.size == 0 {
		return nil
	}
	tail := make([]byte, 1)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("audit: reopen %s to inspect tail: %w", path, err)
	}
	_, err = f.ReadAt(tail, r.size-1)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("audit: read tail of %s: %w", path, err)
	}
	if closeErr != nil {
		return fmt.Errorf("audit: close %s after tail read: %w", path, closeErr)
	}
	if tail[0] == '\n' {
		return nil
	}
	n, err := r.file.Write([]byte{'\n'})
	if err != nil {
		return fmt.Errorf("audit: terminate dangling line in %s: %w", path, err)
	}
	r.size += int64(n)
	return nil
}

// lastLink 读出文件里最后一条完整记录.
//
// 第二个返回值非空表示"接不上前一条链", 并给出人能看懂的原因.
//
// 返回整条而不只是 (seq, hash): 调用方还要看它的 Action 才能判断上一段是不是
// 干净收尾的 (见 ActionClosed).
func lastLink(path string) (Record, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Record{}, fmt.Sprintf("cannot read %s: %v", path, err)
	}
	if len(data) == 0 {
		return Record{}, "audit file is empty"
	}

	// 从末尾往前找最后一个完整的 JSON 行.
	//
	// 最后一行可能是残缺的: 断电时一次写可能只落了一半. 那不是篡改,
	// 是正常的崩溃现象 - 跳过它继续找, 而不是把整个文件判为不可信.
	end := len(data)
	for end > 0 {
		start := end - 1
		for start > 0 && data[start-1] != '\n' {
			start--
		}
		line := data[start:end]
		var rec Record
		if err := json.Unmarshal(trimNewline(line), &rec); err == nil && rec.Hash != "" {
			return rec, ""
		}
		end = start
		for end > 0 && data[end-1] == '\n' {
			end--
		}
	}
	return Record{}, "no complete record found in audit file"
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// Record 把一条审计排进队列. 绝不阻塞调用方.
//
// 审计的调用点遍布权限裁决, 租约, 装包等路径, 其中一些是热路径. 让它们等一次
// 磁盘写入, 等于把审计的成本加到每一次被审计的操作上.
func (r *FileRecorder) Record(ctx context.Context, ev Event) {
	// slog 镜像先走: 即使队列满了, 运维仍然能在 journal 里看到这条.
	r.log.LogAttrs(ctx, slog.LevelInfo, "audit",
		slog.String("action", ev.Action),
		slog.String("subject", ev.Subject),
		slog.Bool("denied", ev.Denied),
		slog.Any("err", ev.Err),
		slog.String("detail", ev.Detail),
	)

	select {
	case r.queue <- ev:
	default:
		// 队列满. 计数, 由写 goroutine 在下一次成功落盘时转成 ChainGap.
		r.dropped.Add(1)
	}
}

// Dropped 是入队失败的累计条数, 供停机时报告.
func (r *FileRecorder) Dropped() uint64 { return r.dropped.Load() }

// Close 排空队列, 写完并关闭文件. 幂等.
func (r *FileRecorder) Close() error {
	r.once.Do(func() { close(r.stop) })
	<-r.done
	return nil
}

func (r *FileRecorder) run() {
	defer close(r.done)

	// 定时器只负责"把攒下的落盘". 它不产生记录, dirty 为假时 sync 直接返回,
	// 所以空闲的机器上这个 tick 是零成本的.
	ticker := time.NewTicker(minSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case ev := <-r.queue:
			r.writeRecord(ev)
		case <-ticker.C:
			r.sync()
		case <-r.stop:
			// 排空: 停机时队列里那些多半正是最要紧的 (撤权, 停机收敛).
			for {
				select {
				case ev := <-r.queue:
					r.writeRecord(ev)
				default:
					r.flushGap()
					// 终结记录 + 无条件 sync, 标志这一段是干净收尾的.
					// 顺序要紧: 先写记录再 sync, 反过来会把它自己漏在缓存里,
					// 于是每次正常停机看起来都像掉电.
					r.append(Event{
						Action:  ActionClosed,
						Subject: "kernel",
						Detail:  fmt.Sprintf("final_seq=%d", r.seq),
					})
					r.sync()
					if r.file != nil {
						_ = r.file.Close()
					}
					return
				}
			}
		}
	}
}

// flushGap 把累计的丢弃数落成一条 ChainGap.
func (r *FileRecorder) flushGap() {
	total := r.dropped.Load()
	if total == r.pending {
		return
	}
	lost := total - r.pending
	r.pending = total
	r.append(Event{
		Action:  ActionChainGap,
		Subject: "kernel",
		Denied:  true,
		Detail:  fmt.Sprintf("lost=%d reason=queue_full", lost),
	})
}

// writeRecord 落一条审计, 必要时先补 ChainGap, 先轮转.
func (r *FileRecorder) writeRecord(ev Event) {
	r.flushGap()
	r.rotateIfNeeded()
	r.append(ev)
	if ev.Denied {
		r.syncIfDue()
	}
}

// append 是唯一真正写文件的地方.
func (r *FileRecorder) append(ev Event) {
	if r.file == nil {
		return
	}
	rec, err := newRecord(r.seq+1, r.prev, r.now(), ev)
	if err != nil {
		r.log.Error("audit: build record", "action", ev.Action, "err", err)
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		r.log.Error("audit: encode record", "action", ev.Action, "err", err)
		return
	}
	line = append(line, '\n')

	n, err := r.file.Write(line)
	if err != nil {
		// 链不前进: seq 与 prev 保持原值, 下一条接着当前链尾.
		// 推进它们会让文件里缺一条却看不出缺 - 正好是要防的那种情况.
		r.log.Error("audit: write record", "action", ev.Action, "err", err)
		r.dropped.Add(1)
		return
	}
	r.size += int64(n)
	r.seq = rec.Seq
	r.prev = rec.Hash
	r.dirty = true
	r.written.Add(1)
}

// sync 把已写入的记录真正落到存储介质上.
//
// Write 返回不等于落盘: 内容躺在内核页缓存里, Linux 默认最多 30 秒才回写.
// 掉电时那 30 秒的记录整段消失, 而剩下的链完全自洽 - 校验工具会报"通过".
// 那是最坏的一种失败: 它给出一个假的确定性.
//
// 只由写 goroutine 调用. dirty 为假时直接返回, 不碰设备.
func (r *FileRecorder) sync() {
	if r.file == nil || !r.dirty {
		return
	}
	if err := r.file.Sync(); err != nil {
		// sync 失败不推进 lastSync 也不清 dirty: 下一次还得再试.
		// 清掉的话就成了"以为落盘了其实没有", 比不 sync 更危险.
		r.log.Error("audit: fsync", "err", err)
		return
	}
	r.dirty = false
	r.lastSync = r.now()
	r.synced.Add(1)
}

// Stats 是给运维和停机日志用的计数.
//
// records 是已落到文件里的条数, syncs 是 fsync 次数. 两者之比说明批量的实际
// 效果; syncs 逼近 records 时值得去看是什么在被反复拒绝.
func (r *FileRecorder) Stats() (records, syncs uint64) {
	return r.written.Load(), r.synced.Load()
}

// syncIfDue 是 Denied 记录走的即时落盘路径, 带 minSyncInterval 节流.
//
// 拒绝类事件是审计里最要紧的一类 (越权尝试, 签名不过, 撤权), 能立刻落盘就
// 立刻落. 但一串连续的拒绝 - 比如某个包被反复拒 - 不该变成一串背靠背的 fsync,
// 那正是逐条 sync 的老问题. 被节流挡下的那条由定时器兜底, 最迟 1 秒后落盘.
func (r *FileRecorder) syncIfDue() {
	if !r.dirty {
		return
	}
	if r.now().Sub(r.lastSync) < minSyncInterval {
		return
	}
	r.sync()
}

// rotateIfNeeded 在超过阈值时轮转, 并在新文件开头接上旧链.
func (r *FileRecorder) rotateIfNeeded() {
	if r.file == nil || r.size < r.maxBytes {
		return
	}
	carry := r.prev
	carrySeq := r.seq

	// 改名之前必须落盘. Close 不隐含 fsync: 旧文件带着没落盘的尾巴变成
	// .1, 掉电后那段就没了 - 而它前面的链依然自洽, 验证工具看不出少了东西.
	// 这里不受 minSyncInterval 节流, 轮转本来就不频繁.
	r.sync()
	if err := r.file.Close(); err != nil {
		r.log.Error("audit: close before rotate", "err", err)
	}
	r.file = nil

	current := filepath.Join(r.dir, FileName)
	// 从最旧往回挪, 避免覆盖. 超出 maxFiles 的那个被丢弃.
	oldest := filepath.Join(r.dir, fmt.Sprintf("%s.%d", FileName, r.maxFiles))
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		r.log.Warn("audit: remove oldest rotated file", "path", oldest, "err", err)
	}
	for i := r.maxFiles - 1; i >= 1; i-- {
		from := filepath.Join(r.dir, fmt.Sprintf("%s.%d", FileName, i))
		to := filepath.Join(r.dir, fmt.Sprintf("%s.%d", FileName, i+1))
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			r.log.Warn("audit: rotate", "from", from, "to", to, "err", err)
		}
	}
	if err := os.Rename(current, filepath.Join(r.dir, FileName+".1")); err != nil {
		r.log.Error("audit: rotate current file", "err", err)
	}

	f, err := os.OpenFile(current, os.O_CREATE|os.O_WRONLY|os.O_APPEND, filePerm)
	if err != nil {
		// 轮转之后打不开新文件: 审计从此刻起只剩 slog. 这是硬故障,
		// 用 Error 让它在 journal 里显眼.
		r.log.Error("audit: open new file after rotate", "err", err)
		return
	}
	r.file = f
	r.size = 0

	// 新文件的第一条带着旧链的末尾. 没有它, 每次轮转在校验工具眼里都是
	// 一次"seq 从 1 重新开始" - 与截断攻击无法分辨.
	//
	// seq 继续递增而不是重置: 链是跨文件的一条, 文件只是它的存储切分.
	r.append(Event{
		Action:  ActionRotated,
		Subject: "kernel",
		Detail:  fmt.Sprintf("carried_seq=%d carried_hash=%s", carrySeq, carry),
	})
}

// ReadFile 读出一个审计文件的全部完整记录, 供校验工具使用.
//
// skipped 是解不开的行数.
//
// # 为什么解不开的行只计数, 不报错
//
// 断电时一次写可能只落了半行. 下一次启动会给它补一个换行让它自成一行
//
//	(见 terminateDanglingLine), 于是文件中间会留下一截解不开的残片 - 那是
//
// 崩溃现象, 不是篡改, 而且它不影响链: 那条记录从来没有被完整写入过,
// 后面的记录接的是它之前那条完整的.
//
// 但必须报出来. skipped 非 0 意味着这台机器上发生过非正常停机, 那是运维
// 需要知道的事. 悄悄跳过会让审计看起来一直很干净.
//
// 真正的篡改 (删记录, 改内容, 调顺序) 由 VerifyChain 抓, 与本函数无关.
func ReadFile(path string) (records []Record, skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: read %s: %w", path, err)
	}

	start := 0
	for i := 0; i <= len(data); i++ {
		if i != len(data) && data[i] != '\n' {
			continue
		}
		line := trimNewline(data[start:i])
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			skipped++
			continue
		}
		records = append(records, rec)
	}
	return records, skipped, nil
}
