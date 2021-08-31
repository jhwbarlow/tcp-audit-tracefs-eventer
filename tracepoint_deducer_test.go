package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

type mockMountpointRetriever struct {
	mountpoint  string
	errToReturn error

	retrieveMountpointCalled bool
}

func newMockMountpointRetriever(mountpoint string, errToReturn error) *mockMountpointRetriever {
	return &mockMountpointRetriever{
		mountpoint:  mountpoint,
		errToReturn: errToReturn,
	}
}

func (mmr *mockMountpointRetriever) retrieveMountpoint() (string, error) {
	mmr.retrieveMountpointCalled = true

	if mmr.errToReturn != nil {
		return "", mmr.errToReturn
	}

	return mmr.mountpoint, nil
}

func TestDeduceTracepointNewKernel(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "sock/inet_sock_set_state"
	mockMountpoint, undoFunc, err := bootstrapMockTraceFS(mockTracepoint, false)
	defer undoFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)

	tracepointDeducer := newTraceFSTracepointDeducer(mockMountpointRetriever)

	tracepoint, err := tracepointDeducer.deduceTracepoint()
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockMountpointRetriever.retrieveMountpointCalled {
		t.Error("expected mountpoint retriever to be called, but was not")
	}

	if tracepoint != mockTracepoint {
		t.Errorf("expected tracepoint %q, got %q", mockTracepoint, tracepoint)
	}

	t.Logf("got tracepoint %q", tracepoint)
}

func TestDeduceTracepointOldKernel(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "tcp/tcp_set_state"
	mockMountpoint, undoFunc, err := bootstrapMockTraceFS(mockTracepoint, false)
	defer undoFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)

	tracepointDeducer := newTraceFSTracepointDeducer(mockMountpointRetriever)

	tracepoint, err := tracepointDeducer.deduceTracepoint()
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockMountpointRetriever.retrieveMountpointCalled {
		t.Error("expected mountpoint retriever to be called, but was not")
	}

	if tracepoint != mockTracepoint {
		t.Errorf("expected tracepoint %q, got %q", mockTracepoint, tracepoint)
	}

	t.Logf("got tracepoint %q", tracepoint)
}

func TestDeduceTracepointNoTracepointsAvailableInKernelError(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against,
	// but with no tracepoint inside
	mockMountpoint, undoFunc, err := bootstrapMockTraceFS("", false)
	defer undoFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}
	
	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)

	tracepointDeducer := newTraceFSTracepointDeducer(mockMountpointRetriever)

	_, err = tracepointDeducer.deduceTracepoint()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestDeduceTracepointNewKernelReadError(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "sock/inet_sock_set_state"
	mockMountpoint, undoFunc, err := bootstrapMockTraceFS(mockTracepoint, true)
	defer undoFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)

	tracepointDeducer := newTraceFSTracepointDeducer(mockMountpointRetriever)

	tracepoint, err := tracepointDeducer.deduceTracepoint()
	t.Logf(tracepoint)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestDeduceTracepointOldKernelReadError(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "tcp/tcp_set_state"
	mockMountpoint, undoFunc, err := bootstrapMockTraceFS(mockTracepoint, true)
	defer undoFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)

	tracepointDeducer := newTraceFSTracepointDeducer(mockMountpointRetriever)

	tracepoint, err := tracepointDeducer.deduceTracepoint()
	t.Logf(tracepoint)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestDeduceTracepointMountpointRetrieverError(t *testing.T) {
	mockError := errors.New("mock mountpoint retriever error")
	mockMountpointRetriever := newMockMountpointRetriever("", mockError)

	tracepointDeducer := newTraceFSTracepointDeducer(mockMountpointRetriever)

	_, err := tracepointDeducer.deduceTracepoint()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func bootstrapMockTraceFS(tracepoint string, inaccessible bool) (string, func(), error) {
	undoFunc := func() {}

	mountpoint, err := ioutil.TempDir("", "ftrace-eventer-test-")
	if err != nil {
		return "", undoFunc, fmt.Errorf("creating temp directory: %w", err)
	}

	undoFunc = func() {
		os.RemoveAll(mountpoint)
	}

	tracepointPath := mountpoint + "/events/" + tracepoint

	if err := os.MkdirAll(tracepointPath, 0700); err != nil {
		return "", undoFunc, fmt.Errorf("creating tracepoint directory structure: %w", err)
	}

	if inaccessible {
		os.Chmod(path.Dir(tracepointPath), 0200)

		undoFunc = func() {
			os.Chmod(path.Dir(tracepointPath), 0700)
			os.RemoveAll(mountpoint)
		}
	}

	return mountpoint, undoFunc, nil
}
