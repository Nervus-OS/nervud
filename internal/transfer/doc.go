// Package transfer owns Nervus' generic high-throughput data plane.
//
// Capability-specific code never appears here. A camera, microphone, file
// importer, or sensor declares a MethodMeta.Transfer policy; the IPC layer
// proves which in-flight route authorized the transfer and passes an immutable
// Origin to Manager.Begin.
//
// The first implementation intentionally supports only FRAMED_RELAY. The
// shared-memory mode remains fail-closed until its memfd/eventfd ABI is frozen.
//
// The data plane is Linux-only and carries no non-Linux fallback. A former
// platform_unsupported.go returned ErrUnsupportedPlatform from every entry
// point; it was removed because nervud never runs anywhere else, and a build
// that compiles but fails at every call turns "this needs Linux" from a
// compile-time fact into a runtime surprise. Build and test on Linux or WSL.
package transfer
