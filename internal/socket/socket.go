package socket

import (
	"context"
)

type Module struct {
	server *Server
}

func (s *Module) Name() string {
	return "socket"
}

func (s *Module) Start(ctx context.Context) error {
	s.server = &Server{}

	if err := s.server.Start(ctx); err != nil {
		return err
	}

	return nil
}

func (s *Module) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Stop()
	}
	return nil
}
