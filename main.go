package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"nervud/internal/empty"
	"nervud/internal/kernel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
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

	k.Register(&empty.EmptyModule{})

	return k.Run(ctx)
}
