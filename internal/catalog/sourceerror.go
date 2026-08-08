package catalog

import "fmt"

// SourceError 标识是哪一个 source 让这次 Build 失败的.
//
// # 为什么需要它
//
// Build 是全有全无的: 任何一个 source 不合法, 整份 Catalog 都构建不出来.
// 对安装路径这正是想要的语义 - 新包有问题就拒绝它, 现有系统不受影响.
//
// 但启动扫描不能是这个语义. pkgregistry.Module 的 Start 注释承诺
// "一个坏包不该拖垮整条内核启动序列", 而 Scan 的逐包跳过只覆盖 manifest 解析,
// digest 与验签那一层; Catalog 层的冲突 (资源多管理者, 接口契约不一致,
// 命名空间越权) 此前会让 Start 直接返回错误, 整台机器起不来.
//
// 要在启动时隔离肇事者, 调用方必须知道肇事者是谁. 用 errors.As 取出 PackageID
// 而不是解析错误字符串: 错误文案是会改的, 而这条判定决定一台机器能不能开机.
type SourceError struct {
	PackageID string
	Err       error
}

func (e *SourceError) Error() string {
	if e == nil {
		return "catalog: source error"
	}
	return fmt.Sprintf("catalog: source %q: %v", e.PackageID, e.Err)
}

func (e *SourceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// sourceErrorf 把一个 source 相关的失败包成 SourceError.
func sourceErrorf(packageID string, format string, args ...any) error {
	return &SourceError{PackageID: packageID, Err: fmt.Errorf(format, args...)}
}
