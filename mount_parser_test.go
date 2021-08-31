package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

type mockFieldParser struct {
	nextFieldErrorToReturn       error
	skipFieldErrorToReturn       error
	getTaggedFieldsErrorToReturn error
}

func newMockFieldParser(nextFieldErrorToReturn error,
	skipFieldErrorToReturn error,
	getTaggedFieldsErrorToReturn error) *mockFieldParser {
	return &mockFieldParser{
		nextFieldErrorToReturn:       nextFieldErrorToReturn,
		skipFieldErrorToReturn:       skipFieldErrorToReturn,
		getTaggedFieldsErrorToReturn: getTaggedFieldsErrorToReturn,
	}
}

func (mfp *mockFieldParser) nextField(str *[]byte, sep []byte, expectMoreFields bool) (string, error) {
	return "", mfp.nextFieldErrorToReturn
}

func (mfp *mockFieldParser) skipField(str *[]byte, sep []byte) error {
	return mfp.skipFieldErrorToReturn
}

func (mfp *mockFieldParser) getTaggedFields(str *[]byte) (map[string]string, error) {
	return nil, mfp.getTaggedFieldsErrorToReturn
}

type mockReader struct {
	errorToReturn       error
	waitBeforeReturning *sync.WaitGroup
}

func newMockReader(errorToReturn error, waitBeforeReturning *sync.WaitGroup) *mockReader {
	return &mockReader{
		errorToReturn:       errorToReturn,
		waitBeforeReturning: waitBeforeReturning,
	}
}

func (mr *mockReader) Read(p []byte) (int, error) {
	if mr.waitBeforeReturning != nil {
		mr.waitBeforeReturning.Wait()
	}

	return 0, mr.errorToReturn
}

func TestMountsParser(t *testing.T) {
	mockProcMountsFile := "tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0"

	fieldParser := new(slicingFieldParser)
	mountsParser := newProcMountsMountsParser(fieldParser)

	mountpoint, err := mountsParser.getFirstMountpoint(strings.NewReader(mockProcMountsFile), "tracefs")
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if mountpoint != "/sys/kernel/tracing" {
		t.Errorf("expected mountpoint %s, got %s", "/sys/kernel/tracing", mountpoint)
	}
}

func TestMountsParserNoMatchingFilesystemError(t *testing.T) {
	mockProcMountsFile := "foofs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0"

	fieldParser := new(slicingFieldParser)
	mountsParser := newProcMountsMountsParser(fieldParser)

	_, err := mountsParser.getFirstMountpoint(strings.NewReader(mockProcMountsFile), "tracefs")
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestMountsParserFieldParserError(t *testing.T) {
	mockProcMountsFile := " "
	mockError := errors.New("mock field parser error")
	mockFieldParser := newMockFieldParser(mockError, nil, nil)
	mountsParser := newProcMountsMountsParser(mockFieldParser)

	_, err := mountsParser.getFirstMountpoint(strings.NewReader(mockProcMountsFile), "tracefs")
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestMountsParserReaderError(t *testing.T) {
	mockFieldParser := newMockFieldParser(nil, nil, nil)
	mockError := errors.New("mock reader error")
	mockReader := newMockReader(mockError, nil)
	mountsParser := newProcMountsMountsParser(mockFieldParser)

	_, err := mountsParser.getFirstMountpoint(mockReader, "tracefs")
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestMountsParserNoMountpointError(t *testing.T) {
	mockProcMountsFile := "tracefs "

	fieldParser := new(slicingFieldParser)
	mountsParser := newProcMountsMountsParser(fieldParser)

	_, err := mountsParser.getFirstMountpoint(strings.NewReader(mockProcMountsFile), "tracefs")
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}
