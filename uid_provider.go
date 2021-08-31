package main

import "github.com/google/uuid"

const (
	prefix = "tcp-audit-"
)

// UidProvider is an interface which describes objects which provide
// a unique string.
type uidProvider interface {
	uid() string
}

// UuidProvider provides a UUID string prefixed with "tcp-audit-"
type uuidProvider struct{}

// Uid returns a UUID string prefixed with "tcp-audit-"
func (*uuidProvider) uid() string {
	return prefix + uuid.NewString()
}
