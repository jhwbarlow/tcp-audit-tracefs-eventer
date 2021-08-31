package main

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorPanicToErr(t *testing.T) {
	var returnError error
	mockError := errors.New("mock panic error")

	defer func(t *testing.T, err *error, expectedWrappedErr error) {
		if *err == nil {
			t.Error("expected error, got nil")
		}

		t.Logf("got error %q (of type %T)", *err, *err)

		if !errors.Is(*err, mockError) {
			t.Errorf("expected error chain to include %q, but did not", mockError)
		}
	}(t, &returnError, mockError)

	defer panicToErr("testing panic-to-error", &returnError)

	panic(mockError)
}

func TestGenericPanicToErr(t *testing.T) {
	var returnError error
	mockError := "mock panic error"

	defer func(t *testing.T, err *error, expectedWrappedErr string) {
		if *err == nil {
			t.Error("expected error, got nil")
		}

		t.Logf("got error %q (of type %T)", *err, *err)

		if !strings.Contains((*err).Error(), mockError) {
			t.Errorf("expected error string to include %q, but did not", mockError)
		}
	}(t, &returnError, mockError)

	defer panicToErr("testing panic-to-error", &returnError)

	panic(mockError)
}
