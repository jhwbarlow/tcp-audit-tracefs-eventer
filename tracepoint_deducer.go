package main

import (
	"errors"
	"fmt"
	"os"
)

// TracepointDeducer is an interface which describes objects which deduce
// which tracepoint to use, based upon what is available in the running kernel.
type tracepointDeducer interface {
	deduceTracepoint() (string, error)
}

// TraceFSTracepointDeducer deduces what tracepoint to use, based upon what is
// available in the tracefs virtual filesystem.
type traceFSTracepointDeducer struct {
	mountpointRetriever mountpointRetriever
}

func newTraceFSTracepointDeducer(mountpointRetriever mountpointRetriever) *traceFSTracepointDeducer {
	return &traceFSTracepointDeducer{mountpointRetriever}
}

// DeduceTracepoint returns the tracepoint to use based upon what is
// available in the running kernel. An error is returned if the kernel
// exposes no relevant tracepoints.
func (td *traceFSTracepointDeducer) deduceTracepoint() (string, error) {
	traceFSMountpoint, err := td.mountpointRetriever.retrieveMountpoint()
	if err != nil {
		return "", fmt.Errorf("obtaining tracefs mountpoint: %w", err)
	}

	// Check the tracepoint is available in the running kernel
	_, err = os.Stat(traceFSMountpoint + "/events/sock/inet_sock_set_state")
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("checking if inet_sock_set_state event present: %w", err)
	}

	if err != nil && os.IsNotExist(err) {
		// Older kernel version has same event but with less fields in /events/tcp/tcp_set_state
		// The missing fields are not a problem, as we dont care about those anyway!
		_, err := os.Stat(traceFSMountpoint + "/events/tcp/tcp_set_state")
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("checking if tcp_set_state event present: %w", err)
		}

		if err != nil && os.IsNotExist(err) {
			return "", errors.New("required tracepoint not available")
		}

		return "tcp/tcp_set_state", nil
	}

	return "sock/inet_sock_set_state", nil
}
