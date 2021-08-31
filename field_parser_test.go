package main

import (
	"io"
	"testing"
)

func TestGetTaggedFields(t *testing.T) {
	mockTags := []byte("foo=hello bar=world baz=123")

	fieldParser := new(slicingFieldParser)
	fields, err := fieldParser.getTaggedFields(&mockTags)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	foo, ok := fields["foo"]
	if !ok {
		t.Errorf("expected %q to be present in map, but was not", "foo")
	}
	if foo != "hello" {
		t.Errorf("expected %q key to have %q value in map, but was %q", "foo", "hello", foo)
	}

	bar, ok := fields["bar"]
	if !ok {
		t.Errorf("expected %q to be present in map, but was not", "bar")
	}
	if bar != "world" {
		t.Errorf("expected %q key to have %q value in map, but was %q", "bar", "world", bar)
	}

	baz, ok := fields["baz"]
	if !ok {
		t.Errorf("expected %q to be present in map, but was not", "baz")
	}
	if baz != "123" {
		t.Errorf("expected %q key to have %q value in map, but was %q", "baz", "123", baz)
	}

	if len(mockTags) != 0 {
		t.Logf(string(mockTags))
		t.Errorf("expected all bytes in slice to be consumed, but were not (len: %d)", len(mockTags))
	}
}

func TestGetTaggedFieldsTagNoValueEOFError(t *testing.T) {
	mockTags := []byte("foo=")

	fieldParser := new(slicingFieldParser)
	_, err := fieldParser.getTaggedFields(&mockTags)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetTaggedFieldsTagNoValueError(t *testing.T) {
	mockTags := []byte("foo= ")

	fieldParser := new(slicingFieldParser)
	_, err := fieldParser.getTaggedFields(&mockTags)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetTaggedFieldsTagNoValueDataFollowsError(t *testing.T) {
	mockTags := []byte("foo= bar=baz")

	fieldParser := new(slicingFieldParser)
	_, err := fieldParser.getTaggedFields(&mockTags)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetTaggedFieldsTagNoSeparatorError(t *testing.T) {
	mockTags := []byte("foo")

	fieldParser := new(slicingFieldParser)
	_, err := fieldParser.getTaggedFields(&mockTags)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestGetSeperatedFields(t *testing.T) {
	mockStream := []byte("foo bar baz")

	fieldParser := new(slicingFieldParser)
	field, err := fieldParser.nextField(&mockStream, []byte(" "), true)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if field != "foo" {
		t.Errorf("expected %q field, but got %q", "foo", field)
	}

	field, err = fieldParser.nextField(&mockStream, []byte(" "), true)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if field != "bar" {
		t.Errorf("expected %q field, but got %q", "bar", field)
	}

	field, err = fieldParser.nextField(&mockStream, []byte(" "), false)
	switch err {
	case io.EOF:
		// Expected
	case nil:
		t.Error("expected EOF error, got nil")
	default:
		t.Errorf("expected EOF error, got %v (of type %T)", err, err)
	}

	if field != "baz" {
		t.Errorf("expected %q field, but got %q", "baz", field)
	}
}

func TestGetSeperatedFieldsNoFieldFollowsError(t *testing.T) {
	mockStream := []byte("foo")

	fieldParser := new(slicingFieldParser)
	_, err := fieldParser.nextField(&mockStream, []byte(" "), true)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestSkipSeperatedField(t *testing.T) {
	mockStream := []byte("foo bar")

	fieldParser := new(slicingFieldParser)
	if _, err := fieldParser.nextField(&mockStream, []byte(" "), true); err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	field, err := fieldParser.nextField(&mockStream, []byte(" "), false)
	switch err {
	case io.EOF:
		// Expected
	case nil:
		t.Error("expected EOF error, got nil")
	default:
		t.Errorf("expected EOF error, got %v (of type %T)", err, err)
	}

	if field != "bar" {
		t.Errorf("expected %q field, but got %q", "bar", field)
	}
}
