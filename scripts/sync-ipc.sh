#!/usr/bin/env bash
# 把本仓库依赖的完整 nervus-ipc module 同步到指定版本（默认最新）。
#
# 为什么需要一个脚本而不是直接 go get：
#
#   1. GOPRIVATE 是必需的。nervus-ipc 是本组织自己的模块，刚推的 commit 在
#      sum.golang.org 上往往还没索引，直接 go get 会撞 500。GOPRIVATE 让 Go
#      跳过公共校验和数据库与代理，直连 GitHub。go.sum 仍然记录哈希，首次
#      拉取之后的任何篡改照样会被发现——关掉的是「第三方为我背书」，不是
#      「校验」本身。
#
#   2. 忘记同步的后果很隐蔽。内核曾经长时间钉在 ipc 的 init commit 上，
#      期间协议侧新增的 safety / schema / method_registry / provider_descriptor /
#      ControlLease 内核【一个都看不见】，但编译和测试全绿——因为它没引用
#      那些类型。等到有人要接线时才发现符号根本不存在。
#
# 用法：
#   scripts/sync-ipc.sh              同步到 master 最新
#   scripts/sync-ipc.sh <commit|tag> 同步到指定版本
#
# nervus-ipc 的 go.mod 位于仓库根目录，tag 不再使用旧的 go/ 子目录前缀。

set -euo pipefail

REF="${1:-master}"
MODULE="github.com/nervus-os/nervus-ipc"

cd "$(dirname "$0")/.."

echo "==> 同步 ${MODULE}@${REF}"
GOPRIVATE="github.com/nervus-os/*" GOPROXY=direct GOFLAGS=-mod=mod \
	go get "${MODULE}@${REF}"

echo "==> go mod tidy"
GOPRIVATE="github.com/nervus-os/*" GOPROXY=direct go mod tidy

echo "==> 当前版本"
grep nervus-ipc go.mod

# 同步后立刻验证：协议变更可能引入不兼容的字段/枚举改名，
# 越早撞见越好——不要等到某个模块接线时才发现。
echo "==> 编译与静态检查"
go build ./...
go vet ./...

echo "==> 测试（内核是 //go:build linux，本步必须在 Linux/WSL 上跑）"
go test ./...

echo "✅ 同步完成"
