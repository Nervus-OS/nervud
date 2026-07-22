// Package ipc 承载控制面通信：AF_UNIX/SOCK_STREAM + uint32 大端长度前缀 +
// Protobuf Envelope + Nervus RPC/Event/Subscription 语义。入口为 /run/nervus/nervud.sock
package ipc
