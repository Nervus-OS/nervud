//go:build linux

package transfer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcsdk "github.com/nervus-os/nervus-ipc/sdk"
	"golang.org/x/sys/unix"
)

// SHARED_MEMORY_RING 的内核侧：建 memfd + eventfd，经 SCM_RIGHTS 分发给两端。
//
// ABI 定义在 nervus-ipc 的 transfer.proto（TransferRingConfig）与 sdk/ring.go。
// 本文件只负责【创建与分发】，不参与数据流——ring 模式下 nervud 不在热路径上，
// 这正是它相对 FRAMED_RELAY 的全部意义。
//
// # 内核为什么必须自己建而不是让 Provider 建
//
// 让 Provider 建 memfd 再交给内核转发，等于让被授权方决定授权对象的大小与内容。
// 内核建、内核封口、内核分发，两端拿到的几何参数才与控制面下发的那份必然一致。

// ringSlotCount 是环的 slot 数。
//
// 8 是在「吸收抖动」与「内存占用」之间的取值：1080p 编码流每帧几十 KB，8 帧
// 足以吸收消费者一次调度延迟；而 4K 裸帧 12 MiB × 8 = 96 MiB，已经是不该用
// FRAMED_RELAY 之外任何方式硬扛的量级。必须是 2 的幂（掩码取模）。
const ringSlotCount = 8

// ringResources 是一次 ring 传输的内核侧资源。
type ringResources struct {
	memFD   *os.File
	eventFD *os.File
	config  *ipcv1.TransferRingConfig
}

func (r *ringResources) close() {
	if r == nil {
		return
	}
	if r.memFD != nil {
		_ = r.memFD.Close()
	}
	if r.eventFD != nil {
		_ = r.eventFD.Close()
	}
}

// newRingResources 建一个 ring 所需的 memfd 与 eventfd，并写好环头部。
//
// slotSize 取生效后的 maxPacket——两者必须相等，否则 Provider 写一个合法大小的
// 包会溢出 slot。
func newRingResources(slotSize uint32) (*ringResources, error) {
	geometry := ipcsdk.RingGeometry{
		SlotCount:       ringSlotCount,
		SlotSize:        slotSize,
		HeaderBytes:     ipcsdk.RingHeaderBytes,
		DescriptorBytes: ipcsdk.RingDescriptorBytes,
	}
	total, err := geometry.TotalBytes()
	if err != nil {
		return nil, err
	}

	// MFD_ALLOW_SEALING：封口之后连内核自己都不能再改大小，两端因此可以信任
	// 「映射长度 == 控制面下发的几何」这条不变量
	fd, err := unix.MemfdCreate("nervud-transfer-ring", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("transfer: memfd_create: %w", err)
	}
	memFD := os.NewFile(uintptr(fd), "nervud-transfer-ring")

	if err := unix.Ftruncate(int(memFD.Fd()), int64(total)); err != nil {
		_ = memFD.Close()
		return nil, fmt.Errorf("transfer: ftruncate ring: %w", err)
	}

	// 先写头部再封口：封口之后 mmap 写入仍然允许（F_SEAL_WRITE 会阻止），
	// 因此这里只封大小，不封写——两端都要往 ring 里写自己的游标
	mem, err := unix.Mmap(int(memFD.Fd()), 0, int(total),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = memFD.Close()
		return nil, fmt.Errorf("transfer: mmap ring: %w", err)
	}
	initErr := ipcsdk.InitHeader(mem, geometry)
	munmapErr := unix.Munmap(mem)
	if initErr != nil {
		_ = memFD.Close()
		return nil, initErr
	}
	if munmapErr != nil {
		_ = memFD.Close()
		return nil, fmt.Errorf("transfer: munmap ring: %w", munmapErr)
	}

	// 只封 SHRINK|GROW：大小从此固定，而两端仍需写各自的游标。
	// 封了 WRITE 的话消费者连自己的 consumer_cursor 都写不了
	if _, err := unix.FcntlInt(memFD.Fd(), unix.F_ADD_SEALS,
		unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		_ = memFD.Close()
		return nil, fmt.Errorf("transfer: seal ring: %w", err)
	}

	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = memFD.Close()
		return nil, fmt.Errorf("transfer: eventfd: %w", err)
	}

	return &ringResources{
		memFD:   memFD,
		eventFD: os.NewFile(uintptr(efd), "nervud-transfer-ring-event"),
		config: &ipcv1.TransferRingConfig{
			SlotCount:       geometry.SlotCount,
			SlotSize:        geometry.SlotSize,
			HeaderBytes:     geometry.HeaderBytes,
			DescriptorBytes: geometry.DescriptorBytes,
		},
	}, nil
}

// sendRingFDs 在 conn 上用 SCM_RIGHTS 发送 memfd 与 eventfd。
//
// 【顺序固定为 memfd, eventfd】，与 transfer.proto 的约定一致。对端收到的数量
// 不等于 2 必须视为协议违规——数量不符说明两侧对 ABI 的理解已经分叉。
//
// 必须与那一字节的载荷【同一次 sendmsg】：SCM_RIGHTS 是附着在数据报上的，
// 分两次发的话对端可能先读到数据、后收到 fd，或者根本收不到。
func sendRingFDs(conn net.Conn, res *ringResources) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("transfer: ring requires a unix connection")
	}
	if res == nil || res.memFD == nil || res.eventFD == nil {
		return errors.New("transfer: ring resources are incomplete")
	}
	rights := unix.UnixRights(int(res.memFD.Fd()), int(res.eventFD.Fd()))
	// 一字节载荷：SCM_RIGHTS 不能附在零长度的 sendmsg 上
	n, oobn, err := unixConn.WriteMsgUnix([]byte{0}, rights, nil)
	if err != nil {
		return fmt.Errorf("transfer: send ring fds: %w", err)
	}
	if n != 1 || oobn != len(rights) {
		return fmt.Errorf("transfer: partial ring fd send (payload %d, oob %d/%d)",
			n, oobn, len(rights))
	}
	return nil
}

// ringModeSupported 报告本机是否支持 ring 模式所需的全部系统调用。
//
// 探测一次而不是每次 Begin 都试：memfd_create 在 Linux 3.17 起可用、
// F_ADD_SEALS 要求 MFD_ALLOW_SEALING，两者在目标平台（RK3588 / 现代内核）
// 恒成立，但开发容器里未必。
func ringModeSupported() bool {
	fd, err := unix.MemfdCreate("nervud-probe", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return false
	}
	_ = syscall.Close(fd)
	return true
}
