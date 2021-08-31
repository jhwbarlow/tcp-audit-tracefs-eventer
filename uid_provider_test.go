package main

import "testing"

func TestUIDProvider(t *testing.T) {
	uidProvider := new(uuidProvider)
	uid := uidProvider.uid()

	if uid == "" {
		t.Errorf("expected UID, got empty string")
	}
}
