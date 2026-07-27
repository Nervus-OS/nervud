package transfer

import "time"

// Limits bounds state, socket, memory, and reserved throughput before a
// provider can allocate them.
type Limits struct {
	MaxTransfers                    int
	MaxTransfersPerUID              int
	MaxTombstones                   int
	MaxPendingAttachments           int
	MaxPendingAttachmentsPerUID     int
	MaxPacketBytes                  uint32
	MaxBytesPerSecond               uint64
	MaxReservedBytesPerSecond       uint64
	MaxReservedBytesPerSecondPerUID uint64
	MaxRelayBufferBytes             uint64
	MaxFramesPerSecond              uint32
	HandshakeTimeout                time.Duration
	ProviderAttachTimeout           time.Duration
	CallerAttachGrace               time.Duration
	MaxHandleLifetime               time.Duration
	IdleTimeout                     time.Duration
	WriteTimeout                    time.Duration
	ReapInterval                    time.Duration
	TombstoneTTL                    time.Duration
}

// DefaultLimits returns conservative production hard ceilings.
func DefaultLimits() Limits {
	return Limits{
		MaxTransfers:                    64,
		MaxTransfersPerUID:              8,
		MaxTombstones:                   1024,
		MaxPendingAttachments:           64,
		MaxPendingAttachmentsPerUID:     8,
		MaxPacketBytes:                  4 << 20,
		MaxBytesPerSecond:               64 << 20,
		MaxReservedBytesPerSecond:       256 << 20,
		MaxReservedBytesPerSecondPerUID: 128 << 20,
		MaxRelayBufferBytes:             256 << 20,
		MaxFramesPerSecond:              1000,
		HandshakeTimeout:                2 * time.Second,
		ProviderAttachTimeout:           5 * time.Second,
		CallerAttachGrace:               5 * time.Second,
		MaxHandleLifetime:               45 * time.Second,
		IdleTimeout:                     30 * time.Second,
		WriteTimeout:                    5 * time.Second,
		ReapInterval:                    250 * time.Millisecond,
		TombstoneTTL:                    30 * time.Second,
	}
}

func normalizeLimits(v Limits) Limits {
	d := DefaultLimits()
	if v.MaxTransfers <= 0 {
		v.MaxTransfers = d.MaxTransfers
	}
	if v.MaxTransfersPerUID <= 0 {
		v.MaxTransfersPerUID = d.MaxTransfersPerUID
	}
	if v.MaxTombstones <= 0 {
		v.MaxTombstones = d.MaxTombstones
	}
	if v.MaxPendingAttachments <= 0 {
		v.MaxPendingAttachments = d.MaxPendingAttachments
	}
	if v.MaxPendingAttachmentsPerUID <= 0 {
		v.MaxPendingAttachmentsPerUID = d.MaxPendingAttachmentsPerUID
	}
	if v.MaxPacketBytes == 0 {
		v.MaxPacketBytes = d.MaxPacketBytes
	}
	if v.MaxBytesPerSecond == 0 {
		v.MaxBytesPerSecond = d.MaxBytesPerSecond
	}
	if v.MaxReservedBytesPerSecond == 0 {
		v.MaxReservedBytesPerSecond = d.MaxReservedBytesPerSecond
	}
	if v.MaxReservedBytesPerSecondPerUID == 0 {
		v.MaxReservedBytesPerSecondPerUID = d.MaxReservedBytesPerSecondPerUID
	}
	if v.MaxRelayBufferBytes == 0 {
		v.MaxRelayBufferBytes = d.MaxRelayBufferBytes
	}
	if v.MaxFramesPerSecond == 0 {
		v.MaxFramesPerSecond = d.MaxFramesPerSecond
	}
	if v.HandshakeTimeout <= 0 {
		v.HandshakeTimeout = d.HandshakeTimeout
	}
	if v.ProviderAttachTimeout <= 0 {
		v.ProviderAttachTimeout = d.ProviderAttachTimeout
	}
	if v.CallerAttachGrace <= 0 {
		v.CallerAttachGrace = d.CallerAttachGrace
	}
	if v.MaxHandleLifetime <= 0 {
		v.MaxHandleLifetime = d.MaxHandleLifetime
	}
	if v.IdleTimeout <= 0 {
		v.IdleTimeout = d.IdleTimeout
	}
	if v.WriteTimeout <= 0 {
		v.WriteTimeout = d.WriteTimeout
	}
	if v.ReapInterval <= 0 {
		v.ReapInterval = d.ReapInterval
	}
	if v.TombstoneTTL <= 0 {
		v.TombstoneTTL = d.TombstoneTTL
	}
	return v
}
