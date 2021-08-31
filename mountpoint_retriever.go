package main

import (
	"fmt"
	"os"
)

// MountpointRetriever is an interface which describes objects which retrieve the tracefs
// mountpoint.
type mountpointRetriever interface {
	retrieveMountpoint() (string, error)
}

// ProcFSMountpointRetriever retrieves the tracefs mountpoint using the /proc/mounts
// virtual file.
type procFSMountpointRetriever struct {
	mountsParser mountsParser

	mountpoint string
}

func newProcFSMountpointRetriever(mountsParser mountsParser) *procFSMountpointRetriever {
	return &procFSMountpointRetriever{mountsParser: mountsParser}
}

// RetrieveMountpoint retrieves the tracefs filesystem mountpoint.
func (mr *procFSMountpointRetriever) retrieveMountpoint() (string, error) {
	if mr.mountpoint != "" {
		return mr.mountpoint, nil
	}

	// It has been observed that tracefs only seems to get mounted by the kernel
	// when the path is first accessed, so poke some likely paths to get it mounted
	dir, err := os.Open("/sys/kernel/debug/tracing")
	dir.Close()
	if err != nil && os.IsNotExist(err) {
		dir, _ := os.Open("/sys/kernel/tracing")
		dir.Close()
	}

	mounts, err := os.Open("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("opening mounts: %w", err)
	}
	defer mounts.Close()

	mountpoint, err := mr.mountsParser.getFirstMountpoint(mounts, "tracefs")
	if err != nil {
		return "", fmt.Errorf("reading virtual device mounts: %w", err)
	}

	return mountpoint, nil
}
