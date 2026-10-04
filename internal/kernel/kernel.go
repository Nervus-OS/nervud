package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const moduleStopTimeout = 10 * time.Second

type contextKey int

const reportFatalKey contextKey = 0

type Module interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

func ReportFatal(ctx context.Context, err error) {
	if err == nil {
		return
	}
	if fn, ok := ctx.Value(reportFatalKey).(func(error)); ok {
		fn(err)
	}
}

type Kernel struct {
	modules []Module
}

func (k *Kernel) Register(m Module) {
	k.modules = append(k.modules, m)
}

func (k *Kernel) Run(ctx context.Context) error {
	slog.Debug("kernel run started", "module_count", len(k.modules))

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	fatalCh := make(chan error, 1)

	reportFatal := func(err error) {
		if err == nil {
			return
		}

		select {
		case fatalCh <- err:
			slog.Debug("fatal error reported by module", "error", err)
		default:
		}

		cancelRun()
	}

	runCtx = context.WithValue(runCtx, reportFatalKey, reportFatal)

	started := make([]Module, 0, len(k.modules))
	var runErr error

	for _, m := range k.modules {
		if runCtx.Err() != nil {
			break
		}

		moduleName := m.Name()
		slog.Debug("starting module", "module", moduleName)

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panic in module %q Start: %v", moduleName, r)
					ReportFatal(runCtx, err)
				}
			}()
			return m.Start(runCtx)
		}()

		if err != nil {
			if !errors.Is(err, context.Canceled) || runCtx.Err() == nil {
				slog.Debug("module failed to start", "module", moduleName, "error", err)
				runErr = fmt.Errorf(
					"start module %q: %w",
					moduleName,
					err,
				)
			}

			cancelRun()
			break
		}

		slog.Debug("module started", "module", moduleName)
		started = append(started, m)
	}

	if runErr == nil {
		if runCtx.Err() == nil {
			slog.Debug("kernel started")
			<-runCtx.Done()
		}
		slog.Debug("kernel shutdown requested", "error", runCtx.Err())
	}

	var stopErr error

	for i := len(started) - 1; i >= 0; i-- {
		m := started[i]
		moduleName := m.Name()
		slog.Debug("stopping module", "module", moduleName)

		stopCtx, cancelStop := context.WithTimeout(
			context.Background(),
			moduleStopTimeout,
		)

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panic in module %q Stop: %v", moduleName, r)
				}
			}()
			return m.Stop(stopCtx)
		}()

		cancelStop()

		if err != nil {
			slog.Debug("module failed to stop", "module", moduleName, "error", err)
			stopErr = errors.Join(
				stopErr,
				fmt.Errorf(
					"stop module %q: %w",
					moduleName,
					err,
				),
			)
		} else {
			slog.Debug("module stopped", "module", moduleName)
		}
	}

	var fatalErr error

	select {
	case fatalErr = <-fatalCh:
	default:
	}

	if runErr == nil && stopErr == nil && fatalErr == nil {
		slog.Debug("kernel run completed successfully")
	}

	return errors.Join(runErr, stopErr, fatalErr)
}
