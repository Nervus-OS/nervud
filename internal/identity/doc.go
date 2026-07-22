// Package identity 负责可信身份：从 socket 读取 SO_PEERCRED（PID/UID/GID）
// 并把 UID 映射到 Package Registry 中的 Package ID。身份来自内核，不信任客户端自报
package identity
