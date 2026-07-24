// 本文件是安装期的 Host ABI 匹配：这个包声明的
// supported_abis 是否包含当前设备的 ABI token。不匹配即拒绝安装 - 容器解决不了
// CPU 指令集与 ABI 不匹配（Agent 决策 ）。
//
// v1 简化：只按 runtime.GOARCH 映射出粗粒度 token 做集合匹配。端序、libc、
// ARM float ABI、最低 ISA、C++ runtime 等更细的兼容边界
// 属于多架构制品选择的 v2 范围，这里不展开 - 但 token 词法本身（拒绝 Android
// NDK 名、拒绝裸 CPU 名）已在 manifest.validate 严格执行
package pkgregistry

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrABIMismatch 包声明的 supported_abis 不含当前 Host 的 ABI token
var ErrABIMismatch = errors.New("pkgregistry: package does not support this host ABI")

// hostABIToken 返回当前设备的 canonical NSOS ABI token
//
// 空字符串表示本平台不在 v1 支持集内（如 Windows/darwin 开发机） - 此时
// checkHostABI 放行，避免在非 Linux 开发环境下把每次装包测试都判成 ABI 不匹配；
// 真正的设备上 GOARCH 必落在下面三者之一
func hostABIToken() string {
	switch runtime.GOARCH {
	case "arm64":
		return ABILinuxArm64
	case "arm":
		return ABILinuxArmv7
	case "amd64":
		return ABILinuxX86_64
	default:
		return ""
	}
}

// checkHostABI 校验 supported 是否包含当前 Host 的 ABI token
func checkHostABI(supported []string) error {
	host := hostABIToken()
	if host == "" {
		return nil // 非目标平台（开发机）：不做 Host 匹配
	}
	for _, abi := range supported {
		if abi == host {
			return nil
		}
	}
	return fmt.Errorf("%w: host %q, package supports %v", ErrABIMismatch, host, supported)
}
