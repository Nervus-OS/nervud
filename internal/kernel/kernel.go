package kernel

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const moduleStopTimeout = 10 * time.Second

type Module interface {
	Name() string
	Start(ctx context.Context, reportFatal func(error)) error
	Stop(ctx context.Context) error
}

type Kernel struct {
	modules []Module
}

func (k *Kernel) Register(m Module) {
	k.modules = append(k.modules, m)
}

func (k *Kernel) Run(ctx context.Context) error {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	fatalCh := make(chan error, 1)

	reportFatal := func(err error) {
		if err == nil {
			return
		}

		select {
		case fatalCh <- err:
		default:
		}

		cancelRun()
	}

	started := make([]Module, 0, len(k.modules))
	var runErr error

	for _, m := range k.modules {
		if runCtx.Err() != nil {
			break
		}

		if err := m.Start(runCtx, reportFatal); err != nil {
			if !errors.Is(err, context.Canceled) || runCtx.Err() == nil {
				runErr = fmt.Errorf(
					"start module %q: %w",
					m.Name(),
					err,
				)
			}

			cancelRun()
			break
		}

		started = append(started, m)
	}

	if runErr == nil && runCtx.Err() == nil {
		<-runCtx.Done()
	}

	var stopErr error

	for i := len(started) - 1; i >= 0; i-- {
		m := started[i]

		stopCtx, cancelStop := context.WithTimeout(
			context.Background(),
			moduleStopTimeout,
		)

		err := m.Stop(stopCtx)
		cancelStop()

		if err != nil {
			stopErr = errors.Join(
				stopErr,
				fmt.Errorf(
					"stop module %q: %w",
					m.Name(),
					err,
				),
			)
		}
	}

	var fatalErr error

	select {
	case fatalErr = <-fatalCh:
	default:
	}

	return errors.Join(runErr, stopErr, fatalErr)
}
