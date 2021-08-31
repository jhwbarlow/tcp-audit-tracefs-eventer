package main

import (
	"bufio"
	"fmt"
	"io"
)

// MountsParser is an interface which describes objects which retrieve the first
// mountpoint of a given filesystem type.
type mountsParser interface {
	getFirstMountpoint(reader io.Reader, fsType string) (string, error)
}

// ProcMountsMountsParser retrieves the first mountpoint of a given virtual filesystem type.
// It expects the input to be in the same format as the /proc/mounts virtual file.
type procMountsMountsParser struct {
	fieldParser fieldParser
}

func newProcMountsMountsParser(fieldParser fieldParser) *procMountsMountsParser {
	return &procMountsMountsParser{fieldParser}
}

// GetFirstMountpoint retrieves the first mountpoint of a given virtual filesystem type.
// It expects the input to be in the same format as the /proc/mounts virtual file.
// This implementation relies upon the fact that in /proc/mounts, the device name is the
// same as the virtual filesystem name.
func (mp *procMountsMountsParser) getFirstMountpoint(reader io.Reader, fsType string) (string, error) {
	scanner := bufio.NewScanner(reader)
	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", fmt.Errorf("scanning mounts for %s mountpoint: %w", fsType, err)
			}

			// EOF reached but no mountpoint found
			return "", fmt.Errorf("%s not mounted", fsType)
		}

		mount := scanner.Bytes()
		device, err := mp.fieldParser.nextField(&mount, spaceBytes, true) // Get device from mount
		if err != nil {
			return "", fmt.Errorf("getting device from mount: %w", err)
		}

		if string(device) == fsType {
			mountpoint, err := mp.fieldParser.nextField(&mount, spaceBytes, true) // Get mountpoint from mount
			if err != nil {
				return "", fmt.Errorf("getting mountpoint from mount: %w", err)
			}

			// Mountpoint successfully located
			return mountpoint, nil
		}
	}
}
