// install 之前崩溃/放弃时，会在 staging 根留下未提交的目录。它们不影响正确性
// （install 只认显式提交的路径），但会占磁盘，因此每次 begin-staging 时best-effort
// 回收太老的。
package admin

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// staleStagingAge 是 staging 目录被视为孤儿、可回收的年龄阈值。取 1 小时：
// 远长于任何正常begin -> 解包 -> install的耗时（秒级），又不至于让孤儿长期
// 堆积。清扫是best-effort，宁可漏删也绝不误删正在用的。
const staleStagingAge = time.Hour

// stagingPrefix 是 begin-staging 建目录用的前缀（os.MkdirTemp 的 pattern）。清扫
// 只碰这个前缀的目录，绝不动 staging 根下的其它东西。
const stagingPrefix = "stage-"

// sweepStaleStaging 删掉 staging 根下超过 staleStagingAge 的 stage-* 目录。全程
// best-effort：任何一步失败只记日志、不阻断 begin-staging（磁盘回收不该拖垮装包）。
func (s *Server) sweepStaleStaging() {
	entries, err := os.ReadDir(s.stagingRoot)
	if err != nil {
		// staging 根还不存在/读不了：begin-staging 的 MkdirTemp 会给出更明确的错误，
		// 这里静默返回即可。
		return
	}
	cutoff := time.Now().Add(-staleStagingAge)
	for _, ent := range entries {
		if !ent.IsDir() || !strings.HasPrefix(ent.Name(), stagingPrefix) {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue // 还年轻，可能正被某个 CLI 使用
		}
		dir := filepath.Join(s.stagingRoot, ent.Name())
		if err := os.RemoveAll(dir); err != nil {
			s.log.Warn("admin: failed to sweep stale staging dir", "dir", dir, "err", err)
		}
	}
}
