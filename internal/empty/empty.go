package empty

import "context"

type EmptyModule struct{}

func (e *EmptyModule) Name() string {
	return "empty"
}

func (e *EmptyModule) Start(ctx context.Context, reportFatal func(error)) error {
	<-ctx.Done()
	return nil
}

func (e *EmptyModule) Stop(ctx context.Context) error {
	return nil
}
