package kernel

/*
Empty module:

    package empty

    import "context"

    type Module struct{}

    func (e *Module) Name() string {
        return "empty"
    }

    func (e *Module) Start(ctx context.Context, reportFatal func(error)) error {
        <-ctx.Done()
        return nil
    }

    func (e *Module) Stop(ctx context.Context) error {
        return nil
    }
*/
