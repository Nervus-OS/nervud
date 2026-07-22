// Package authority 是所有 Linux 特权操作的唯一入口（Authority Gate）
// 只有本包可以直接 import os/exec、syscall、golang.org/x/sys/unix
// 对外只暴露固定、类型化、窄范围的接口（如 StartSandboxedProcess、StopProcess）
// 严禁提供 RunAsRoot/ExecuteShell 一类的任意执行能力
package authority
