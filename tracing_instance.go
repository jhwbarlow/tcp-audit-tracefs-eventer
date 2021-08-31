package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// TracingInstance is an interface which describes objects which expose a ring
// buffer of TCP state change tracing events from the kernel.
type tracingInstance interface {
	open() (io.Reader, error)
	enable() error
	disable() error
	close() error
}

// TraceFSTracingInstance creates a unique tracefs tracing instance and exposes
// the trace_pipe ring buffer of TCP state change tracing events from the kernel.
type traceFSTracingInstance struct {
	mountpointRetriever mountpointRetriever
	tracepointDeducer   tracepointDeducer
	uidProvider         uidProvider

	path string
	pipe *os.File
}

func newTraceFSTracingInstance(mountpointRetriever mountpointRetriever,
	tracepointDeducer tracepointDeducer,
	uidProvider uidProvider) *traceFSTracingInstance {

	return &traceFSTracingInstance{
		mountpointRetriever: mountpointRetriever,
		tracepointDeducer:   tracepointDeducer,
		uidProvider:         uidProvider,
	}
}

// Enable creates a tracefs instance within the retrieved mountpoint and
// enables the tracepoint provided by the tracepoint deducer, ready for the
// open method to be called.
func (ti *traceFSTracingInstance) enable() error {
	// Check whether and where tracefs is mounted
	traceFSMountpoint, err := ti.mountpointRetriever.retrieveMountpoint()
	if err != nil {
		return fmt.Errorf("obtaining tracefs mountpoint: %w", err)
	}

	// Find the tracepoint to use depending on kernel version
	tracepoint, err := ti.tracepointDeducer.deduceTracepoint()
	if err != nil {
		return fmt.Errorf("getting tracepoint: %w", err)
	}

	ti.path = traceFSMountpoint + "/instances/" + ti.uidProvider.uid()
	if err := os.Mkdir(ti.path, 0600); err != nil && !os.IsExist(err) {
		return fmt.Errorf("making instance directory: %w", err)
	}

	if err := ti.enableTracePoint(tracepoint); err != nil {
		return fmt.Errorf("enabling tracepoint: %w", err)
	}

	if err := ti.enableTracing(); err != nil {
		return fmt.Errorf("enabling tracing: %w", err)
	}

	return nil
}

// Disable cleans up the tracefs instance. It should be called once
// the tracing instance has been closed.
func (ti *traceFSTracingInstance) disable() error {
	log.Printf("Removing tracing instance: %s", ti.path)
	if err := os.RemoveAll(ti.path); err != nil {
		return fmt.Errorf("removing tracing instance: %w", err)
	}

	return nil
}

func (ti *traceFSTracingInstance) enableTracing() error {
	if err := ioutil.WriteFile(ti.path+"/tracing_on", []byte("1\n"), 0); err != nil {
		return fmt.Errorf("setting tracing_on: %w", err)
	}

	return nil
}

func (ti *traceFSTracingInstance) enableTracePoint(tracepoint string) error {
	if err := ioutil.WriteFile(ti.path+"/events/"+tracepoint+"/enable",
		[]byte("1\n"), 0); err != nil {
		return fmt.Errorf("enabling tracepoint %q: %w", tracepoint, err)
	}

	return nil
}

// Open opens the tracefs trace_pipe ring buffer from which TCP
// state change events can be read.
func (ti *traceFSTracingInstance) open() (io.Reader, error) {
	tracePipe, err := os.Open(ti.path + "/trace_pipe")
	if err != nil {
		return nil, fmt.Errorf("opening trace_pipe: %w", err)
	}

	ti.pipe = tracePipe
	return tracePipe, nil
}

// Close closes the tracefs trace_pipe ring buffer.
func (ti *traceFSTracingInstance) close() error {
	log.Printf("Closing trace pipe: %s", ti.pipe.Name())
	if err := ti.pipe.Close(); err != nil {
		return fmt.Errorf("closing trace pipe: %w", err)
	}

	return nil
}
