package main

import (
	"context"
	"log/slog"
	"nervud/internal/config"
	"nervud/internal/eventbus"
	"nervud/internal/kernel"
	"nervud/internal/registry"
	"nervud/internal/socket"
	"nervud/internal/virtual"
	"os"
	"os/signal"
	"syscall"

	"github.com/lmittmann/tint"
)

func main() {
	// Log level setting
	slog.SetDefault(slog.New(
		tint.NewTextHandler(os.Stderr, &tint.Options{
			Level: slog.LevelDebug,
		}),
	))

	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	k := &kernel.Kernel{}

	k.Register(&config.Module{})
	k.Register(&eventbus.Module{})
	k.Register(&registry.Module{})
	k.Register(&virtual.Module{})
	k.Register(&socket.Module{})

	return k.Run(ctx)
}
