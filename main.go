package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
)

var ErrEventerClosed = errors.New("read from closed eventer")

type Eventer struct {
	tracingInstance tracingInstance
	scanner         *bufio.Scanner
	eventParser     eventParser

	closedMutex *sync.Mutex
	closed      bool
}

func New() (e event.Eventer, err error) {
	fieldParser := new(slicingFieldParser)
	virtualDeviceMountsParser := newProcMountsMountsParser(fieldParser)
	mountpointRetriever := newProcFSMountpointRetriever(virtualDeviceMountsParser)
	tracepointDeducer := newTraceFSTracepointDeducer(mountpointRetriever)
	uidProvider := new(uuidProvider)
	tracingInstance := newTraceFSTracingInstance(mountpointRetriever,
		tracepointDeducer,
		uidProvider)
	eventParser := newTraceFSEventParser(fieldParser)

	return newEventer(tracingInstance, eventParser)
}

func newEventer(tracingInstance tracingInstance,
	eventParser eventParser) (*Eventer, error) {
	if err := tracingInstance.enable(); err != nil {
		return nil, fmt.Errorf("enabling tracing instance: %w", err)
	}

	// Open the tracing instance for reading
	traceRingBuf, err := tracingInstance.open()
	if err != nil {
		tracingInstance.disable()
		return nil, fmt.Errorf("opening tracing instance: %w", err)
	}

	return &Eventer{
		tracingInstance: tracingInstance,
		scanner:         bufio.NewScanner(traceRingBuf),
		eventParser:     eventParser,
		closedMutex:     new(sync.Mutex),
		closed:          false,
	}, nil
}

func (e *Eventer) Event() (*event.Event, error) {
	e.closedMutex.Lock()
	if e.closed {
		return nil, ErrEventerClosed
	}
	e.closedMutex.Unlock()

	for {
		if !e.scanner.Scan() {
			if err := e.scanner.Err(); err != nil {
				e.closedMutex.Lock()
				if e.closed {
					return nil, fmt.Errorf("closed while scanning: %w", ErrEventerClosed)
				}
				e.closedMutex.Unlock()

				return nil, fmt.Errorf("scanning for event: %w", err)
			}

			// No error is still an error - a ring buffer should never return EOF,
			// instead, reads should block until something is written
			return nil, io.ErrUnexpectedEOF
		}

		str := e.scanner.Bytes()
		if len(str) == 0 {
			continue
		}

		event, err := e.eventParser.toEvent(str)
		if err != nil {
			if err == errIrrelevantEvent {
				continue
			}

			return nil, fmt.Errorf("parsing event: %w", err)
		}

		return event, nil
	}
}

func (e *Eventer) Close() error {
	e.closedMutex.Lock()
	// Setting this flag will cause Event() to no longer attempt to read from
	// the trace buffer and suppress any errors reported from a closed tracing
	// instance
	e.closed = true
	e.closedMutex.Unlock()

	if err := e.tracingInstance.close(); err != nil {
		return fmt.Errorf("closing tracing instance: %w", err)
	}

	// TODO: Attempt disable if close fails

	if err := e.tracingInstance.disable(); err != nil {
		return fmt.Errorf("disabling tracing instance: %w", err)
	}

	return nil
}
