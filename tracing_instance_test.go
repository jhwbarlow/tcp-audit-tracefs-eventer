package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type mockUIDProvider struct {
	uidToReturn string

	uidCalled bool
}

func newMockUIDProvider(uidToReturn string) *mockUIDProvider {
	return &mockUIDProvider{uidToReturn: uidToReturn}
}

func (mup *mockUIDProvider) uid() string {
	mup.uidCalled = true

	return mup.uidToReturn
}

type mockTracepointDeducer struct {
	tracepointToReturn string
	errorToReturn      error

	deduceTracepointCalled bool
}

func newMockTracepointDeducer(tracepointToReturn string,
	errorToReturn error) *mockTracepointDeducer {
	return &mockTracepointDeducer{
		tracepointToReturn: tracepointToReturn,
		errorToReturn:      errorToReturn,
	}
}

func (mtd *mockTracepointDeducer) deduceTracepoint() (string, error) {
	mtd.deduceTracepointCalled = true

	if mtd.errorToReturn != nil {
		return "", mtd.errorToReturn
	}

	return mtd.tracepointToReturn, nil
}

func TestTracingInstance(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "sock/inet_sock_set_state"
	mockMountpoint, undoMockTraceFSFunc, err := bootstrapMockTraceFS(mockTracepoint, false)
	defer undoMockTraceFSFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	// Create a fake tracefs-like instance directory structure, within the
	// fake tracefs. The instance is given a known name, which we can pass to
	// a mock UID provider to ensure the TraceFSTracingInstance uses this fake
	// tracefs instance
	mockInstanceName := "mock-instance"
	undoMockTraceFSInstanceFunc, err := bootstrapMockTraceFSInstance(mockMountpoint,
		mockInstanceName,
		mockTracepoint,
		false,
		false,
		false)
	defer undoMockTraceFSInstanceFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs instance: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)
	mockTracepointDeducer := newMockTracepointDeducer(mockTracepoint, nil)
	mockUIDProvider := newMockUIDProvider(mockInstanceName)
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	if err := tracingInstance.enable(); err != nil {
		t.Errorf("expected nil enable error, got %q (of type %T)", err, err)
	}

	// Check the tracing instance called the expected dependencies
	if !mockMountpointRetriever.retrieveMountpointCalled {
		t.Error("expected mountpoint retriever to be called, but was not")
	}

	if !mockTracepointDeducer.deduceTracepointCalled {
		t.Error("expected tracepoint deducer to be called, but was not")
	}

	if !mockUIDProvider.uidCalled {
		t.Error("expected UID provider to be called, but was not")
	}

	// Check the tracing instance performed the correct tracefs modifications
	tracepointEnableFileContents, err := readTracepointEnableFile(mockMountpoint,
		mockInstanceName,
		mockTracepoint)
	if err != nil {
		t.Fatalf("running test: unable to read tracepoint enable file contents: %v", err)
	}

	instanceTracingOnFileContents, err := readInstanceTracingOnFile(mockMountpoint,
		mockInstanceName)
	if err != nil {
		t.Fatalf("running test: unable to read instance tracing_on file contents: %v", err)
	}

	if tracepointEnableFileContents != "1" {
		t.Errorf("expected tracepoint enable file to contain %q, but contained %q", "1",
			tracepointEnableFileContents)
	}

	if instanceTracingOnFileContents != "1" {
		t.Errorf("expected instance tracing_on file to contain %q, but contained %q", "1",
			instanceTracingOnFileContents)
	}

	// Check opening the instance is OK and refers to a trace_pipe file
	reader, err := tracingInstance.open()
	if err != nil {
		t.Errorf("expected nil open error, got %q (of type %T)", err, err)
	}

	tracePipeFile := reader.(*os.File)
	filename := path.Base(tracePipeFile.Name())
	if filename != "trace_pipe" {
		t.Errorf("expected trace_pipe file to be opened, but was %s", filename)
	}

	// Check closing the instance is OK
	if err := tracingInstance.close(); err != nil {
		t.Errorf("expected nil close error, got %q (of type %T)", err, err)
	}

	// Check disabling the instance destroys the created resources
	if err := tracingInstance.disable(); err != nil {
		t.Errorf("expected nil disable error, got %q (of type %T)", err, err)
	}

	exists, err := instanceExists(mockMountpoint, mockInstanceName)
	if err != nil {
		t.Fatalf("running test: unable to check if instance exists: %v", err)
	}

	if exists {
		t.Error("expected instance to be removed, but was not")
	}
}

func TestTracingInstanceMountpointRetrieverError(t *testing.T) {
	mockError := errors.New("mock mountpoint retriever error")
	mockMountpointRetriever := newMockMountpointRetriever("", mockError)
	mockTracepointDeducer := newMockTracepointDeducer("", nil)
	mockUIDProvider := newMockUIDProvider("")
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	err := tracingInstance.enable()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestTracingInstanceTracepointDeducerError(t *testing.T) {
	mockError := errors.New("mock tracepoint deducer error")
	mockMountpointRetriever := newMockMountpointRetriever("", nil)
	mockTracepointDeducer := newMockTracepointDeducer("", mockError)
	mockUIDProvider := newMockUIDProvider("")
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	err := tracingInstance.enable()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestTracingInstanceCreateInstanceError(t *testing.T) {
	mockMountpointPath := os.TempDir() + "/" + uuid.NewString() // Will not exist
	mockMountpointRetriever := newMockMountpointRetriever(mockMountpointPath, nil)
	mockTracepointDeducer := newMockTracepointDeducer("", nil)
	mockUIDProvider := newMockUIDProvider("")
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	err := tracingInstance.enable()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestTracingInstanceEnableTracepointError(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "sock/inet_sock_set_state"
	mockMountpoint, undoMockTraceFSFunc, err := bootstrapMockTraceFS(mockTracepoint, false)
	defer undoMockTraceFSFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	// Create a fake tracefs-like instance directory structure, within the
	// fake tracefs. The instance is given a known name, which we can pass to
	// a mock UID provider to ensure the TraceFSTracingInstance uses this fake
	// tracefs instance
	mockInstanceName := "mock-instance"
	undoMockTraceFSInstanceFunc, err := bootstrapMockTraceFSInstance(mockMountpoint,
		mockInstanceName,
		mockTracepoint,
		true,
		false,
		false)
	defer undoMockTraceFSInstanceFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs instance: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)
	mockTracepointDeducer := newMockTracepointDeducer(mockTracepoint, nil)
	mockUIDProvider := newMockUIDProvider(mockInstanceName)
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	err = tracingInstance.enable()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestTracingInstanceTracingOnError(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "sock/inet_sock_set_state"
	mockMountpoint, undoMockTraceFSFunc, err := bootstrapMockTraceFS(mockTracepoint, false)
	defer undoMockTraceFSFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	// Create a fake tracefs-like instance directory structure, within the
	// fake tracefs. The instance is given a known name, which we can pass to
	// a mock UID provider to ensure the TraceFSTracingInstance uses this fake
	// tracefs instance
	mockInstanceName := "mock-instance"
	undoMockTraceFSInstanceFunc, err := bootstrapMockTraceFSInstance(mockMountpoint,
		mockInstanceName,
		mockTracepoint,
		false,
		true,
		false)
	defer undoMockTraceFSInstanceFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs instance: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)
	mockTracepointDeducer := newMockTracepointDeducer(mockTracepoint, nil)
	mockUIDProvider := newMockUIDProvider(mockInstanceName)
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	err = tracingInstance.enable()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestTracingInstanceOpenError(t *testing.T) {
	// Create a fake tracefs-like directory structure to test against
	mockTracepoint := "sock/inet_sock_set_state"
	mockMountpoint, undoMockTraceFSFunc, err := bootstrapMockTraceFS(mockTracepoint, false)
	defer undoMockTraceFSFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs: %v", err)
	}

	// Create a fake tracefs-like instance directory structure, within the
	// fake tracefs. The instance is given a known name, which we can pass to
	// a mock UID provider to ensure the TraceFSTracingInstance uses this fake
	// tracefs instance
	mockInstanceName := "mock-instance"
	undoMockTraceFSInstanceFunc, err := bootstrapMockTraceFSInstance(mockMountpoint,
		mockInstanceName,
		mockTracepoint,
		false,
		false,
		true)
	defer undoMockTraceFSInstanceFunc()
	if err != nil {
		t.Fatalf("test bootstrapping: unable to create mock tracefs instance: %v", err)
	}

	mockMountpointRetriever := newMockMountpointRetriever(mockMountpoint, nil)
	mockTracepointDeducer := newMockTracepointDeducer(mockTracepoint, nil)
	mockUIDProvider := newMockUIDProvider(mockInstanceName)
	tracingInstance := newTraceFSTracingInstance(mockMountpointRetriever,
		mockTracepointDeducer,
		mockUIDProvider)

	if err = tracingInstance.enable(); err != nil {
		t.Errorf("expected nil open error, got %q (of type %T)", err, err)
	}

	_, err = tracingInstance.open()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func bootstrapMockTraceFSInstance(mountpoint,
	instance,
	tracepoint string,
	enableFileInaccessible,
	tracingOnFileInaccessible,
	tracePipeFileInaccessible bool) (func(), error) {
	undoFunc := func() {}
	instancePath := mountpoint + "/instances/" + instance
	tracepointPath := instancePath + "/events/" + tracepoint

	if err := os.MkdirAll(tracepointPath, 0700); err != nil {
		return undoFunc, fmt.Errorf("creating instance tracepoint directory structure: %w", err)
	}

	undoFunc = func() {
		os.RemoveAll(instancePath)
	}

	// Create enable file for tracepoint
	if err := ioutil.WriteFile(tracepointPath+"/enable", []byte{}, 0600); err != nil {
		return undoFunc, fmt.Errorf("creating instance tracepoint enable file: %w", err)
	}

	if enableFileInaccessible {
		os.Chmod(tracepointPath+"/enable", 0400)

		undoFunc = func() {
			os.Chmod(tracepointPath+"/enable", 0600)
			os.RemoveAll(instancePath)
		}
	}

	// Create tracing_on file for instance
	if err := ioutil.WriteFile(instancePath+"/tracing_on", []byte{}, 0600); err != nil {
		return undoFunc, fmt.Errorf("creating instance tracing_on file: %w", err)
	}

	if tracingOnFileInaccessible {
		os.Chmod(instancePath+"/tracing_on", 0400)

		undoFunc = func() {
			os.Chmod(instancePath+"/tracing_on", 0600)
			os.RemoveAll(instancePath)
		}
	}

	// Create a trace_pipe file for instance
	if err := ioutil.WriteFile(instancePath+"/trace_pipe", []byte{}, 0600); err != nil {
		return undoFunc, fmt.Errorf("creating instance trace_pipe file: %w", err)
	}

	if tracePipeFileInaccessible {
		os.Chmod(instancePath+"/trace_pipe", 0200)

		undoFunc = func() {
			os.Chmod(instancePath+"/trace_pipe", 0600)
			os.RemoveAll(instancePath)
		}
	}

	return undoFunc, nil
}

func readTracepointEnableFile(mountpoint, instance, tracepoint string) (string, error) {
	instancePath := mountpoint + "/instances/" + instance
	tracepointPath := instancePath + "/events/" + tracepoint

	contents, err := ioutil.ReadFile(tracepointPath + "/enable")
	if err != nil {
		return "", fmt.Errorf("reading instance tracepoint enable file: %w", err)
	}

	return strings.Trim(string(contents), "\n"), nil
}

func readInstanceTracingOnFile(mountpoint, instance string) (string, error) {
	instancePath := mountpoint + "/instances/" + instance

	contents, err := ioutil.ReadFile(instancePath + "/tracing_on")
	if err != nil {
		return "", fmt.Errorf("reading instance tracing_on file: %w", err)
	}

	return strings.Trim(string(contents), "\n"), nil
}

func instanceExists(mountpoint, instance string) (bool, error) {
	instancePath := mountpoint + "/instances/" + instance

	if _, err := os.Stat(instancePath); err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("checking instance exists: %w", err)
		}

		return false, nil
	}

	return true, nil
}
