package main

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
)

type mockTraceInstance struct {
	openReaderToReturn io.Reader

	openErrorToReturn    error
	enableErrorToReturn  error
	closeErrorToReturn   error
	disableErrorToReturn error

	openCalled    bool
	enableCalled  bool
	closeCalled   bool
	disableCalled bool
}

func newMockTraceInstance(openReaderToReturn io.Reader,
	openErrorToReturn error,
	enableErrorToReturn error,
	closeErrorToReturn error,
	disableErrorToReturn error) *mockTraceInstance {
	return &mockTraceInstance{
		openReaderToReturn:   openReaderToReturn,
		openErrorToReturn:    openErrorToReturn,
		enableErrorToReturn:  enableErrorToReturn,
		disableErrorToReturn: disableErrorToReturn,
		closeErrorToReturn:   closeErrorToReturn,
	}
}

func (mti *mockTraceInstance) open() (io.Reader, error) {
	mti.openCalled = true

	if mti.openErrorToReturn != nil {
		return nil, mti.openErrorToReturn
	}

	return mti.openReaderToReturn, nil
}

func (mti *mockTraceInstance) enable() error {
	mti.enableCalled = true

	if mti.enableErrorToReturn != nil {
		return mti.enableErrorToReturn
	}

	return nil
}

func (mti *mockTraceInstance) disable() error {
	mti.disableCalled = true

	if mti.disableErrorToReturn != nil {
		return mti.disableErrorToReturn
	}

	return nil
}

func (mti *mockTraceInstance) close() error {
	mti.closeCalled = true

	if mti.closeErrorToReturn != nil {
		return mti.closeErrorToReturn
	}

	return nil
}

type mockEventParser struct {
	eventToReturn          *event.Event
	errorToReturn          error
	noOfTimesToReturnError int

	toEventCalled bool

	errorsReturnedCount int
}

func newMockEventParser(eventToReturn *event.Event,
	errorToReturn error,
	noOfTimesToReturnError int) *mockEventParser {
	return &mockEventParser{
		eventToReturn:          eventToReturn,
		errorToReturn:          errorToReturn,
		noOfTimesToReturnError: noOfTimesToReturnError,
	}
}

func (mep *mockEventParser) toEvent(str []byte) (*event.Event, error) {
	mep.toEventCalled = true

	if mep.errorToReturn != nil && mep.errorsReturnedCount < mep.noOfTimesToReturnError {
		mep.errorsReturnedCount++
		return nil, mep.errorToReturn
	}

	return mep.eventToReturn, nil
}

func TestEventerConstructorEnablesAndOpensTraceInstance(t *testing.T) {
	mockReader := new(bytes.Buffer)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	_, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockTraceInstance.enableCalled {
		t.Error("expected trace instance to be enabled, but was not")
	}

	if !mockTraceInstance.openCalled {
		t.Error("expected trace instance to be opened, but was not")
	}
}

func TestEventerConstructorTraceInstanceEnableError(t *testing.T) {
	mockReader := new(bytes.Buffer)
	mockError := errors.New("mock trace instance enable error")
	mockTraceInstance := newMockTraceInstance(mockReader, nil, mockError, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	_, err := newEventer(mockTraceInstance, mockEventParser)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestEventerConstructorTraceInstanceOpenError(t *testing.T) {
	mockError := errors.New("mock trace instance open error")
	mockTraceInstance := newMockTraceInstance(nil, mockError, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	_, err := newEventer(mockTraceInstance, mockEventParser)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}

	if !mockTraceInstance.disableCalled {
		t.Error("expected trace instance to be disabled, but was not")
	}
}

func TestEventerCloseClosesAndDisablesTraceInstance(t *testing.T) {
	mockReader := new(bytes.Buffer)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	if err := eventer.Close(); err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockTraceInstance.closeCalled {
		t.Error("expected trace instance to be closed, but was not")
	}

	if !mockTraceInstance.disableCalled {
		t.Error("expected trace instance to be disabled, but was not")
	}
}

func TestEventerCloseTraceInstanceCloseError(t *testing.T) {
	mockReader := new(bytes.Buffer)
	mockError := errors.New("mock trace instance close error")
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, mockError, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	err = eventer.Close()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestEventerCloseTraceInstanceDisableError(t *testing.T) {
	mockReader := new(bytes.Buffer)
	mockError := errors.New("mock trace instance disable error")
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, mockError)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	err = eventer.Close()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestEventerEvent(t *testing.T) {
	mockReader := strings.NewReader("mock event data\n")
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}
}

func TestEventerEventSkipIrrelevantEvent(t *testing.T) {
	mockEventStream := `mock irrelevant event
mockNextEvent
` // The scanner expects newline delimited events
	mockReader := strings.NewReader(mockEventStream)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, errIrrelevantEvent, 1)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}
}

func TestEventerEventSkipSpuriousEmptyEvent(t *testing.T) {
	mockEventStream := "\nmockNextEvent\n" // The scanner expects newline delimited events
	mockReader := strings.NewReader(mockEventStream)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}
}

func TestEventerEventUnexpectedEOFError(t *testing.T) {
	mockReader := strings.NewReader("") // Empty reader should return EOF
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected error chain to include %q, but did not", io.ErrUnexpectedEOF)
	}
}

func TestEventerEventEventParserError(t *testing.T) {
	mockReader := strings.NewReader("mock event data\n")
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockError := errors.New("mock event parser error")
	mockEventParser := newMockEventParser(nil, mockError, 1)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestEventerEventScannerError(t *testing.T) {
	mockError := errors.New("mock reader error")
	mockReader := newMockReader(mockError, nil)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestEventerEventAfterCloseError(t *testing.T) {
	mockReader := new(bytes.Buffer)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	if err := eventer.Close(); err != nil {
		t.Errorf("expected nil close error, got %q (of type %T)", err, err)
	}

	_, err = eventer.Event()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, ErrEventerClosed) {
		t.Errorf("expected error chain to include %q, but did not", ErrEventerClosed)
	}
}

func TestEventerEventAfterCloseWhileScanningError(t *testing.T) {
	wait := new(sync.WaitGroup)
	mockError := errors.New("mock reader closed error")
	mockReader := newMockReader(mockError, wait)
	mockTraceInstance := newMockTraceInstance(mockReader, nil, nil, nil, nil)
	mockEventParser := newMockEventParser(nil, nil, 0)

	eventer, err := newEventer(mockTraceInstance, mockEventParser)
	if err != nil {
		t.Errorf("expected nil constructor error, got %q (of type %T)", err, err)
	}

	wait.Add(1)
	errChan := make(chan error)

	go func(errChan chan<- error) {
		_, err := eventer.Event() // Will block on reader blocking for wait.Done()
		errChan <- err
	}(errChan)

	runtime.Gosched() // A nasty hack to ensure the above (eventer) goroutine has a chance to run and be blocked before the waitgroup is Done() below
	if err := eventer.Close(); err != nil {
		t.Errorf("expected nil close error, got %q (of type %T)", err, err)
	}

	wait.Done() // Unlock eventer goroutine

	err = <-errChan // Wait for eventer goroutine to return
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, ErrEventerClosed) {
		t.Errorf("expected error chain to include %q, but did not", ErrEventerClosed)
	}
}
