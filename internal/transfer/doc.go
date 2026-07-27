// Package transfer owns Nervus' generic high-throughput data plane.
//
// Capability-specific code never appears here. A camera, microphone, file
// importer, or sensor declares a MethodMeta.Transfer policy; the IPC layer
// proves which in-flight route authorized the transfer and passes an immutable
// Origin to Manager.Begin.
//
// The first implementation intentionally supports only FRAMED_RELAY. The
// shared-memory mode remains fail-closed until its memfd/eventfd ABI is frozen.
package transfer
