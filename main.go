package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"nervud/internal/kernel"
)

func main() {
	// Log level setting
	slog.SetDefault(slog.New(slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelDebug},
	)))

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

	// k.Register(&empty.EmptyModule{})

	return k.Run(ctx)
}
