// 见 doc.go 的包说明
//
// 本文件是开发者选项里【影响安装裁决】的那几个开关（应用层架构决策 §8.1）。
//
// 为什么权威状态在内核而不是 settingsd：这些开关直接放宽安装裁决，必须由内核
// 自己持有、自己读取，不能是一个可被普通配置写权限改动的文件。它落在
// /var/lib/nervus/registry/ 下（0700，只有 nervud 能读写），与其它记账状态同域。
//
// 两条永不放宽（在 install.go/upgrade.go 落实，不在这里表达）：
//   - trust 上限：即便 allow_unverified_signature，包仍是 Ordinary；
//   - 签名连续性（lineage 后继）：防身份劫持与数据窃取，devmode 也不放宽。
package pkgregistry

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const devModeStateFile = "_devmode.json"

// DevMode 是安装裁决相关的开发者开关集合
//
// 只放安装裁决用得到的字段。debug_bridge / stay_awake 等属于 service/session 的
// 职责，不在这里复制一份
type DevMode struct {
	Enabled                  bool `json:"-"`
	AllowUnverifiedSignature bool `json:"allow_unverified_signature"`
	AllowDowngrade           bool `json:"allow_downgrade"`
	SkipOEMCountersign       bool `json:"skip_oem_countersign"`
}

// 磁盘形态：{ "enabled": bool, "options": { ... } }（应用层架构决策 §8.1）
type devModeFile struct {
	Enabled bool    `json:"enabled"`
	Options DevMode `json:"options"`
}

// loadDevMode 读取 devmode 记账文件；文件不存在或损坏都返回“全关”
//
// 每次安装现读而不是缓存：devmode 可在运行期由系统设置切换，缓存会让刚关掉的
// 开关在下一次安装仍然生效。损坏时保守地当作“全关”——一个读不出来的 devmode
// 绝不能被当成“放宽全部”
func loadDevMode(stateDir string) DevMode {
	data, err := os.ReadFile(filepath.Join(stateDir, devModeStateFile))
	if err != nil {
		return DevMode{}
	}
	var f devModeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return DevMode{}
	}
	opts := f.Options
	opts.Enabled = f.Enabled
	if !f.Enabled {
		// 未启用开发者模式时，任何单项开关都不生效
		return DevMode{}
	}
	return opts
}
