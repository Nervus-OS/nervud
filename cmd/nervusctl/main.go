// Command nervusctl 是 nervud 的本地特权运维 CLI：装包/卸载/列表/停用启用/授撤权。
//
// 它【不常驻、不持有 Registry 真源】。真源永远是 nervud 进程内的 pkgregistry
// （架构红线 §10：单写者）。nervusctl 只把命令经特权管理通道（internal/adminwire）
// 投递给 nervud，由 nervud 执行并复核——签名验证/裁决全部在 nervud，不在 CLI。
//
// 唯一由 CLI 承担的重活是把 .nspkg 解包成 staging 目录（zstd+tar，含防 tar-slip
// 逃逸），且解包目标是 nervud 经 begin-staging 发回的、它自己掌控的目录。nervud
// 随后对 staging 里的每个文件重新做 digest 复核，因此 CLI 解包环节即便被做手脚也
// 会在 nervud 侧被拒——CLI 不是信任锚。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nervus-os/nervud/internal/adminwire"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// usage 打印命令总览。放进变量以便 -h 与参数错误共用。
const usage = `nervusctl — nervud Local privileged O&M tool

Usage:
  nervusctl [--sock PATH] <command> [arguments...]

Commands:
  install <file.nspkg>              Unpack and trigger installation
  uninstall <package_id>            Uninstall a Package
  list                              List installed Packages
  enable <package_id> <component>   Enable a Component
  disable <package_id> <component>  Disable a Component
  grant <package_id> <permission>   Grant a runtime (dangerous) permission
  revoke <package_id> <permission>  Revoke a runtime permission

Options:
  --sock PATH   Admin channel socket path
`

// run 是可测的入口：解析参数、构造客户端、执行子命令。返回进程退出码。
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nervusctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("sock", adminwire.DefaultSockPath, "admin channel socket path")
	fs.Usage = func() { outf(stderr, "%s", usage) }

	if err := fs.Parse(args); err != nil {
		return 2 // flag 已打印错误
	}
	rest := fs.Args()
	if len(rest) == 0 {
		outf(stderr, "%s", usage)
		return 2
	}

	client := adminwire.NewClient(*sock)
	cmd, cmdArgs := rest[0], rest[1:]

	var err error
	switch cmd {
	case "install":
		err = cmdInstall(client, cmdArgs, stdout)
	case "uninstall":
		err = cmdUninstall(client, cmdArgs, stdout)
	case "list":
		err = cmdList(client, cmdArgs, stdout)
	case "enable":
		err = cmdSetEnabled(client, cmdArgs, stdout, true)
	case "disable":
		err = cmdSetEnabled(client, cmdArgs, stdout, false)
	case "grant":
		err = cmdSetPermission(client, cmdArgs, stdout, adminwire.GrantStateGranted)
	case "revoke":
		err = cmdSetPermission(client, cmdArgs, stdout, adminwire.GrantStateDenied)
	case "help", "-h", "--help":
		outf(stdout, "%s", usage)
		return 0
	default:
		outf(stderr, "nervusctl: unknown command %q\n\n%s", cmd, usage)
		return 2
	}

	if err != nil {
		var ue usageErr
		if errors.As(err, &ue) {
			outf(stderr, "nervusctl: %s\n\n%s", ue.msg, usage)
			return 2
		}
		outf(stderr, "nervusctl: %v\n", err)
		return 1
	}
	return 0
}

// usageErr 标注「参数用法错误」，与运行期失败区分：前者退出 2 并打印用法，
// 后者退出 1。
type usageErr struct{ msg string }

func (e usageErr) Error() string { return e.msg }

func badUsage(format string, args ...any) error {
	return usageErr{msg: fmt.Sprintf(format, args...)}
}

// respErr 把一个失败的 Response 转成 error（供子命令统一处理）。
func respErr(resp adminwire.Response) error {
	if resp.Message != "" {
		return fmt.Errorf("%s (%s)", resp.Message, resp.Code)
	}
	return fmt.Errorf("command failed (%s)", resp.Code)
}
