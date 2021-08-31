package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	colonSpaceBytes = []byte(": ")
	spaceBytes      = []byte{' '}
	equalsBytes     = []byte{'='}
)

// ErrEmptyField is an error returned if the field read from
// the provided byte stream is empty.
var errEmptyField = errors.New("empty field")

// FieldParser is an interface which describes objects which parse byte slices/"streams"
// into their component fields, advancing the position of the provided stream in the
// provided stream to after the returned field(s).
type fieldParser interface {
	nextField(str *[]byte, sep []byte, expectMoreFields bool) (string, error)
	getTaggedFields(str *[]byte) (map[string]string, error)
}

// SlicingFieldParser parses byte slices/"streams" into their component fields, advancing
// the position of the provided stream in the provided stream to after the returned field(s).
// Fields are extracted using byte-slicing techniques.
type slicingFieldParser struct{}

// NextField returns the next field in the stream, the end of the field being delimited by the
// bytes supplied in sep. If sep is not found, then the field is assumed to continue to the end
// of the stream, unless expectMoreFields is true, in which case io.ErrUnexpectedEOF is returned.
func (*slicingFieldParser) nextField(str *[]byte, sep []byte, expectMoreFields bool) (field string, err error) {
	defer panicToErr("parsing next field", &err) // Catch any unexpected slicing errors without panicking

	if len(*str) == 0 { // There can't be a field if there is no more data!
		return "", io.ErrUnexpectedEOF
	}

	idx := bytes.Index(*str, sep)
	if idx == -1 {
		if expectMoreFields {
			return "", io.ErrUnexpectedEOF
		}

		// If the next seperator is not found, assume that the next token is the last in the str
		field = string((*str)[:len(*str)])
		*str = (*str)[len(*str):] // Consume the bytes from the stream just for parity with the other case
		return field, io.EOF
	}

	field = string((*str)[:idx])
	*str = (*str)[idx+len(sep):] // Consume the bytes from the stream so the next read begins after this field

	if len(field) == 0 {
		return "", errEmptyField
	}

	return field, nil
}

// GetTaggedFields returns a map representing a set of tagged fields, the definition of a tagged
// field being one in the form of `key=value`. The stream is expected to consist entirely of space-
// separated tagged fields, otherwise an error is returned.
func (fp *slicingFieldParser) getTaggedFields(str *[]byte) (map[string]string, error) {
	fields := make(map[string]string, 20)
	for {
		nextTag, err := fp.nextField(str, equalsBytes, true) // Expect at least a value after the tag
		if err != nil {
			return nil, fmt.Errorf("parsing next tag: %w", err)
		}

		nextValue, err := fp.nextField(str, spaceBytes, false) // We cannot expect any more fields as this may be the last
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("parsing next tagged value: %w", err)
		}

		fields[nextTag] = nextValue

		if err == io.EOF { // No more fields in stream
			break
		}
	}

	return fields, nil
}
