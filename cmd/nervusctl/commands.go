// 本文件是各子命令的实现：把参数校验、（install 的）解包、调用管理通道、结果
// 展示串起来。所有安全判定都在 nervud 侧，这里只做参数检查与人类可读输出。
package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/nervus-os/nervud/internal/adminwire"
)

// outf/outln 是对 fmt.Fprintf/Fprintln 的最小封装：向用户终端写字节若失败
// （stdout/stderr 已断），CLI 无从补救，故有意丢弃写错误。集中在这里丢弃，
// 而不是在每个调用点散落 `_, _ =`，也让 errcheck 满意。
func outf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func outln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }

// cmdInstall：begin-staging -> 解包 .nspkg 进 nervud 掌控的目录 -> install。
func cmdInstall(c *adminwire.Client, args []string, out io.Writer) error {
	if len(args) != 1 {
		return badUsage("install requires exactly one <file.nspkg>")
	}
	nspkgPath := args[0]
	if _, err := os.Stat(nspkgPath); err != nil {
		return fmt.Errorf("open package: %w", err)
	}

	// 1) 让 nervud 建一个它掌控的 staging 目录（同一文件系统、属主/权限受控）。
	beginResp, err := c.Do(adminwire.Request{Cmd: adminwire.CmdBeginStaging})
	if err != nil {
		return err
	}
	if !beginResp.OK || beginResp.StagingDir == "" {
		return respErr(beginResp)
	}
	staging := beginResp.StagingDir

	// 2) 解包 .nspkg 到该目录（zstd+tar，含防 tar-slip）。失败时 nervud 的 staging
	// 清扫会best-effort回收孤儿，这里不必远程清理。
	if err := unpackNspkg(nspkgPath, staging); err != nil {
		return fmt.Errorf("unpack %s: %w", nspkgPath, err)
	}

	// 3) 触发安装：nervud 复核签名/digest/权限后原子提交。
	resp, err := c.Do(adminwire.Request{Cmd: adminwire.CmdInstall, StagingDir: staging})
	if err != nil {
		return err
	}
	if !resp.OK || resp.Package == nil {
		return respErr(resp)
	}

	p := resp.Package
	outf(out, "installed %s %s (trust=%s, source=%s)\n", p.ID, p.Version, p.Trust, p.Source)
	// 打印授予的权限清单，让操作者能核对安装结果实际获得的权限
	if len(p.Granted) > 0 {
		outln(out, "  granted permissions:")
		for _, perm := range p.Granted {
			outf(out, "    - %s\n", perm)
		}
	} else {
		outln(out, "  granted permissions: (none)")
	}
	return nil
}

// cmdUninstall：卸载一个 Package。
func cmdUninstall(c *adminwire.Client, args []string, out io.Writer) error {
	if len(args) != 1 {
		return badUsage("uninstall requires exactly one <package_id>")
	}
	resp, err := c.Do(adminwire.Request{Cmd: adminwire.CmdUninstall, PackageID: args[0]})
	if err != nil {
		return err
	}
	if !resp.OK {
		return respErr(resp)
	}
	outf(out, "uninstalled %s\n", args[0])
	return nil
}

// cmdList：列出已装 Package（表格输出）。
func cmdList(c *adminwire.Client, args []string, out io.Writer) error {
	if len(args) != 0 {
		return badUsage("list takes no arguments")
	}
	resp, err := c.Do(adminwire.Request{Cmd: adminwire.CmdList})
	if err != nil {
		return err
	}
	if !resp.OK {
		return respErr(resp)
	}
	if len(resp.Packages) == 0 {
		outln(out, "no packages installed")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	outln(tw, "PACKAGE\tVERSION\tTRUST\tSOURCE\tDISABLED")
	for _, p := range resp.Packages {
		disabled := "-"
		if len(p.Disabled) > 0 {
			disabled = fmt.Sprintf("%v", p.Disabled)
		}
		outf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Version, p.Trust, p.Source, disabled)
	}
	return tw.Flush()
}

// cmdSetEnabled：enable/disable 一个 Component（enabled 决定方向）。
func cmdSetEnabled(c *adminwire.Client, args []string, out io.Writer, enabled bool) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	if len(args) != 2 {
		return badUsage("%s requires <package_id> <component_id>", verb)
	}
	resp, err := c.Do(adminwire.Request{
		Cmd: adminwire.CmdSetEnabled, PackageID: args[0], ComponentID: args[1], Enabled: enabled,
	})
	if err != nil {
		return err
	}
	if !resp.OK {
		return respErr(resp)
	}
	outf(out, "%sd %s/%s\n", verb, args[0], args[1])
	return nil
}

// cmdSetPermission：grant/revoke 一个运行期权限（state 决定方向）。
func cmdSetPermission(c *adminwire.Client, args []string, out io.Writer, state string) error {
	verb, past := "revoke", "revoked"
	if state == adminwire.GrantStateGranted {
		verb, past = "grant", "granted"
	}
	if len(args) != 2 {
		return badUsage("%s requires <package_id> <permission>", verb)
	}
	resp, err := c.Do(adminwire.Request{
		Cmd: adminwire.CmdSetPermission, PackageID: args[0], Permission: args[1], GrantState: state,
	})
	if err != nil {
		return err
	}
	if !resp.OK {
		return respErr(resp)
	}
	outf(out, "%s %s %s\n", past, args[0], args[1])
	return nil
}
