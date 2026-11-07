package eventbus

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
)

// Module wraps EventBus to implement the kernel module interface.
// 包装事件总线，使其符合内核的模块接口
type Module struct {
	bus *EventBus
}

// Start initializes and starts the EventBus with default 4 workers.
// 初始化事件总线，默认启动 4 个工作协程
func (m *Module) Start(ctx context.Context) error {
	m.bus = New(4)
	return m.bus.Start(ctx)
}

// Stop stops the EventBus.
func (m *Module) Stop(ctx context.Context) error {
	if m.bus != nil {
		return m.bus.Stop(ctx)
	}
	return nil
}

// Name returns the module name.
func (m *Module) Name() string {
	return "eventbus"
}

// GetBus returns the underlying EventBus instance.
func (m *Module) GetBus() *EventBus {
	return m.bus
}

// EventBus dispatches events to subscribed handlers.
// 将事件分发给已订阅的处理函数
type EventBus struct {
	// handlers map event types to their handler lists.
	handlers   map[reflect.Type]*handlerList
	handlersMu sync.RWMutex

	// eventQueue buffers events for asynchronous dispatch.
	// 暂存事件，供工作协程异步分发
	eventQueue chan *eventWrapper

	workers int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// handlerList stores handlers for one event type.
type handlerList struct {
	handlers map[int]reflect.Value // handlerID -> handler
	nextID   int                   // Next available ID.
	mu       sync.RWMutex
}

// eventWrapper stores an event and its type information.
type eventWrapper struct {
	eventType reflect.Type
	eventVal  reflect.Value
}

// New creates an EventBus. A non-positive workers value uses the default of 4.
// 创建事件总线；工作协程数小于或等于 0 时，默认使用 4 个
func New(workers int) *EventBus {
	if workers <= 0 {
		workers = 4
	}

	return &EventBus{
		handlers:   make(map[reflect.Type]*handlerList),
		eventQueue: make(chan *eventWrapper, 1024),
		workers:    workers,
	}
}

// Subscribe registers a handler for an event type. The handler must have the
// signature func(T) error, where T is the event type.
// 订阅指定类型的事件，处理函数必须接收 T 类型的事件并返回 error
//
// Example:
//
//	unsubscribe, err := bus.Subscribe(func(event *RequestEvent) error {
//	    // Process RequestEvent
//	    return nil
//	})
//	defer unsubscribe()
func (eb *EventBus) Subscribe(handler any) (func(), error) {
	handlerVal := reflect.ValueOf(handler)
	handlerType := handlerVal.Type()

	if handlerType.Kind() != reflect.Func {
		return nil, fmt.Errorf("handler must be a function, got %s", handlerType.Kind())
	}

	if handlerType.NumIn() != 1 {
		return nil, fmt.Errorf("handler must take exactly one argument, got %d", handlerType.NumIn())
	}
	if handlerType.NumOut() != 1 || handlerType.Out(0) != reflect.TypeFor[error]() {
		return nil, fmt.Errorf("handler must return error")
	}

	eventType := handlerType.In(0)

	eb.handlersMu.Lock()
	list, exists := eb.handlers[eventType]
	if !exists {
		list = &handlerList{
			handlers: make(map[int]reflect.Value),
			nextID:   0,
		}
		eb.handlers[eventType] = list
	}
	eb.handlersMu.Unlock()

	list.mu.Lock()
	handlerID := list.nextID
	list.nextID++
	list.handlers[handlerID] = handlerVal
	list.mu.Unlock()

	unsubscribe := func() {
		list.mu.Lock()
		delete(list.handlers, handlerID)
		list.mu.Unlock()
	}

	return unsubscribe, nil
}

// SubscribeWithContext registers a handler and removes it when ctx is canceled.
// The handler must have the signature func(T) error.
// 订阅随 ctx 取消而自动解除；处理函数需接收事件并返回 error
//
// Example:
//
//	err := bus.SubscribeWithContext(ctx, func(event *RequestEvent) error {
//	    // Process RequestEvent
//	    return nil
//	})
func (eb *EventBus) SubscribeWithContext(ctx context.Context, handler any) error {
	unsubscribe, err := eb.Subscribe(handler)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		unsubscribe()
	}()

	return nil
}

// Publish an event asynchronously
// event can be of any type
//
// Example:
//
//	bus.Publish(&RequestEvent{...})
func (eb *EventBus) Publish(event any) {
	if event == nil || eb.eventQueue == nil {
		return
	}

	eventVal := reflect.ValueOf(event)
	eventType := eventVal.Type()

	wrapper := &eventWrapper{
		eventType: eventType,
		eventVal:  eventVal,
	}

	// Send it without blocking; drop the event if the queue is full.
	// 尝试入队，不等待空位；队列已满时丢弃事件
	select {
	case eb.eventQueue <- wrapper:
	default:
		// The queue is full or context is done, so drop the event.
		if eb.ctx != nil {
			select {
			case <-eb.ctx.Done():
			default:
			}
		}
	}
}

// PublishSync dispatches an event immediately and waits until all handlers
// have been started.
// 立即分发事件，等所有处理协程启动后返回，不等待处理完成
func (eb *EventBus) PublishSync(event any) {
	if event == nil {
		return
	}

	eventVal := reflect.ValueOf(event)
	eventType := eventVal.Type()

	wrapper := &eventWrapper{
		eventType: eventType,
		eventVal:  eventVal,
	}

	eb.dispatch(wrapper)
}

// Start starts the event bus workers.
func (eb *EventBus) Start(ctx context.Context) error {
	eb.ctx, eb.cancel = context.WithCancel(ctx)

	for i := 0; i < eb.workers; i++ {
		eb.wg.Add(1)
		go eb.worker()
	}

	return nil
}

// Stop stops the event bus and waits for its workers to exit or for ctx to
// expire.
// 停止事件总线，等待工作协程退出，或在 ctx 结束时返回
func (eb *EventBus) Stop(ctx context.Context) error {
	if eb.cancel != nil {
		eb.cancel()
	}

	if eb.eventQueue != nil {
		close(eb.eventQueue)
	}

	done := make(chan struct{})
	go func() {
		eb.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Name returns the module name.
func (eb *EventBus) Name() string {
	return "eventbus"
}

// worker processes events from the queue.
func (eb *EventBus) worker() {
	defer eb.wg.Done()

	for {
		select {
		case <-eb.ctx.Done():
			return
		case wrapper, ok := <-eb.eventQueue:
			if !ok {
				return
			}
			eb.dispatch(wrapper)
		}
	}
}

// dispatch sends an event to all subscribers concurrently.
// 为各订阅者启动协程，并发处理同一个事件
func (eb *EventBus) dispatch(wrapper *eventWrapper) {
	eb.handlersMu.RLock()
	list, exists := eb.handlers[wrapper.eventType]
	eb.handlersMu.RUnlock()

	if !exists {
		return
	}

	list.mu.RLock()
	// Copy handlers before invoking them so the lock is not held during calls.
	// 先复制处理函数列表，再释放锁调用，避免调用期间一直占锁
	handlers := make([]reflect.Value, 0, len(list.handlers))
	for _, handler := range list.handlers {
		handlers = append(handlers, handler)
	}
	list.mu.RUnlock()

	for _, handler := range handlers {
		go func() {
			args := []reflect.Value{wrapper.eventVal}
			results := handler.Call(args)

			if len(results) > 0 && !results[0].IsNil() {
				err := results[0].Interface().(error)
				slog.Error("event handler error", "error", err)
			}
		}()
	}
}
