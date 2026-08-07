package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nervus-os/nervud/internal/audit"
)

// cmdAuditVerify 校验审计哈希链。
//
// # 它回答的问题
//
// 「这份审计从我上次看它到现在，有没有被改过」。
//
// 校验【跨文件】：轮转后的历史文件与当前文件是同一条链，新文件的第一条带着
// 旧文件的末尾哈希。逐个文件单独校验会在每个文件边界上误报。
//
// # 它不回答的问题
//
// 「有没有人把整份审计重写一遍并重算全链」。那需要外部锚点（远程日志、TPM、
// 一次性写入介质），本工具不假装能做到——见 internal/audit/chain.go 的说明。
func cmdAuditVerify(args []string, stdout io.Writer) error {
	dir := audit.DefaultDir
	switch len(args) {
	case 0:
	case 1:
		dir = args[0]
	default:
		return usageErr{msg: "audit-verify [dir]"}
	}

	files, err := auditFilesOldestFirst(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("nervusctl: no audit files in %s", dir)
	}

	// prev/seq 跨文件串下去，因此必须【从最旧的文件开始】。
	//
	// 起点【不能假设是 seq 1】：轮转的保留策略会丢弃最老的文件，稳态下最旧的
	// 可用文件是从链中间某处开始的。硬要从 1 校验会把一次正常的轮转回收报成
	// 「有记录被删了」——那是最糟的一类误报，它会让真正的告警被当成噪音。
	//
	// 于是以最旧文件的第一条为锚，并在最后说清楚校验覆盖到哪里为止。
	prev := ""
	seq := uint64(0)
	anchored := false
	total := 0
	skippedTotal := 0

	for _, path := range files {
		records, skipped, err := audit.ReadFile(path)
		if err != nil {
			return err
		}
		skippedTotal += skipped
		if !anchored && len(records) > 0 {
			prev = records[0].Prev
			seq = records[0].Seq
			anchored = true
		}
		if idx, err := audit.VerifyChain(records, prev, seq); err != nil {
			// 报出文件与位置：出问题时最要紧的是「从哪一条开始不对」，
			// 那基本就指出了事件发生的时间窗。
			outf(stdout, "FAIL  %s\n", filepath.Base(path))
			if idx >= 0 && idx < len(records) {
				outf(stdout, "      at record seq=%d action=%s\n",
					records[idx].Seq, records[idx].Action)
			}
			return fmt.Errorf("nervusctl: audit chain broken in %s: %w", path, err)
		}
		if n := len(records); n > 0 {
			prev = records[n-1].Hash
			seq = records[n-1].Seq + 1
		}
		total += len(records)
		outf(stdout, "ok    %-20s %d records\n", filepath.Base(path), len(records))
	}

	if !anchored {
		return fmt.Errorf("nervusctl: no complete audit records in %s", dir)
	}

	// 【说清楚校验覆盖了哪一段】。一句「chain verified」而不说起点，会让人
	// 以为整段历史都被验过了——而轮转回收掉的那部分谁也验不了。
	firstRecords, _, err := audit.ReadFile(files[0])
	if err != nil {
		return err
	}
	start := firstRecords[0]
	outf(stdout, "\nchain verified: %d records, seq %d..%d\n", total, start.Seq, seq-1)
	if start.Seq != 1 || start.Prev != "" {
		outf(stdout,
			"note: records before seq %d were rotated out — this run cannot verify them\n",
			start.Seq)
	}
	if skippedTotal > 0 {
		// 【残片不是篡改，但必须报】：它意味着这台机器上发生过非正常停机。
		// 悄悄跳过会让审计看起来一直很干净。
		outf(stdout, "note: %d partial record(s) skipped — the machine was not shut down cleanly\n",
			skippedTotal)
	}
	return nil
}

// auditFilesOldestFirst 按链的时间顺序列出审计文件。
//
// 轮转把当前文件挪成 .1、.1 挪成 .2……所以数字【越大越旧】，
// 而链要从最旧的开始校验。
func auditFilesOldestFirst(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("nervusctl: read %s: %w", dir, err)
	}

	var rotated []string
	hasCurrent := false
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == audit.FileName:
			hasCurrent = true
		case strings.HasPrefix(name, audit.FileName+"."):
			rotated = append(rotated, name)
		}
	}

	// 按后缀数字【降序】：.3 比 .2 旧。
	sort.Slice(rotated, func(i, j int) bool {
		return rotationIndex(rotated[i]) > rotationIndex(rotated[j])
	})

	files := make([]string, 0, len(rotated)+1)
	for _, name := range rotated {
		files = append(files, filepath.Join(dir, name))
	}
	if hasCurrent {
		files = append(files, filepath.Join(dir, audit.FileName))
	}
	return files, nil
}

func rotationIndex(name string) int {
	suffix := strings.TrimPrefix(name, audit.FileName+".")
	n := 0
	for _, c := range suffix {
		if c < '0' || c > '9' {
			// 认不出来的后缀排在最前（当成最旧）。不猜一个顺序：
			// 猜错会让校验从中间开始，报出一个假的链断裂。
			return 1 << 30
		}
		n = n*10 + int(c-'0')
	}
	return n
}
