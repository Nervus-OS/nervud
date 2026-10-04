package socket

import (
	"context"
	"fmt"
	"log/slog"
	"nervud/internal/config"
	"nervud/internal/kernel"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

// Server Unix Domain Socket Server
type Server struct {
	listener net.Listener

	// Connect monitor
	nextConnID atomic.Uint64

	// WaitGroup for goroutines
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Start Socket Server
func (s *Server) Start(ctx context.Context) error {
	SocketPath := config.Get().SocketPath
	SocketPerm := config.Get().SocketPerm

	s.ctx, s.cancel = context.WithCancel(ctx)

	// Ensure /run/nervus directory exists
	if err := os.MkdirAll("/run/nervus", 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	// Remove old socket file (if exists)
	// Unix socket close will not automatically delete the file, need to delete it manually
	if err := os.Remove(SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old socket: %w", err)
	}

	// Create unix socket listener
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", SocketPath, err)
	}
	s.listener = listener

	// Set socket file permission to 0666
	if err := os.Chmod(SocketPath, SocketPerm); err != nil {
		if err := s.listener.Close(); err != nil {
			slog.Error("close listener failed", "error", err)
		}
		return fmt.Errorf("chmod socket: %w", err)
	}

	slog.Info("socket server started", "path", SocketPath)

	// Start Accept loop
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// acceptLoop Accept connection main loop
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			kernel.ReportFatal(s.ctx, fmt.Errorf("accept loop panic: %v", r))
		}
	}()

	for {
		// Accept New Connection
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				// Server closed, exit accept loop
				return
			default:
				slog.Error("accept connection failed", "error", err)
				continue
			}
		}

		// Type assertion to the net.UnixConn
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			slog.Error("not a unix connection")
			if err := conn.Close(); err != nil {
				slog.Error("close connection failed", "error", err)
			}
			continue
		}

		// Assign incremental connection IDs
		connID := s.nextConnID.Add(1)

		// Start a goroutine to handle this connection
		s.wg.Add(1)
		go s.handleConnection(connID, unixConn)
	}
}

// handleConnection Handle single connection
func (s *Server) handleConnection(connID uint64, conn *net.UnixConn) {
	defer s.wg.Done()
	defer conn.Close()

	slog.Info("new connection", "connID", connID, "remote", conn.RemoteAddr())

	// Create a Connection object
	connObj, err := newConnection(s.ctx, connID, conn)
	if err != nil {
		slog.Error("create connection failed", "connID", connID, "error", err)
		return
	}
	// Run connection message loop
	connObj.Run()
}

// Stop the server
func (s *Server) Stop() error {
	slog.Info("stopping socket server")

	SocketPath := config.Get().SocketPath

	// Cancel context, stop Accept loop
	s.cancel()

	// Close listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			slog.Error("close listener failed", "error", err)
		}
	}

	// Wait for all goroutines to exit
	s.wg.Wait()

	// Remove socket file
	if err := os.Remove(SocketPath); err != nil {
		slog.Error("remove socket file failed", "error", err)
	}

	slog.Info("socket server stopped")
	return nil
}
