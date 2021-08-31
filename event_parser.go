package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
	"github.com/jhwbarlow/tcp-audit-common/pkg/tcpstate"
)

const (
	familyInet  = "AF_INET"
	protocolTCP = "IPPROTO_TCP"
)

// ErrIrrelevantEvent is an error returned if the event read from
// the provided byte stream is not a TCPv4 event.
var errIrrelevantEvent error = errors.New("irrelevant event")

// EventParser is an interface which describes objects which convert a byte
// slice/"stream" containing a TCP state-change event into an event object.
type eventParser interface {
	toEvent(str []byte) (*event.Event, error)
}

// TraceFSEventParser is a parser of tracefs TCP state-change events.
type traceFSEventParser struct {
	fieldParser fieldParser
}

func newTraceFSEventParser(fieldParser fieldParser) *traceFSEventParser {
	return &traceFSEventParser{fieldParser}
}

// ToEvent creates a TCP state-change event object from the supplied byte
// slice/"stream"
func (ep *traceFSEventParser) toEvent(str []byte) (*event.Event, error) {
	time := time.Now().UTC()

	command, err := parseCommand(&str)
	if err != nil {
		return nil, fmt.Errorf("parsing command from event: %w", err)
	}

	pidStr, err := ep.fieldParser.nextField(&str, spaceBytes, true)
	if err != nil {
		return nil, fmt.Errorf("parsing PID from event: %w", err)
	}
	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("converting PID to integer: %w", err)
	}

	if _, err := ep.fieldParser.nextField(&str, colonSpaceBytes, true); err != nil {
		return nil, fmt.Errorf("skipping metadata from event: %w", err)
	}

	if _, err := ep.fieldParser.nextField(&str, colonSpaceBytes, true); err != nil {
		return nil, fmt.Errorf("skipping tracepoint from event: %w", err)
	}

	// Begin tagged data
	tags, err := ep.fieldParser.getTaggedFields(&str)
	if err != nil {
		return nil, fmt.Errorf("parsing tagged fields: %w", err)
	}

	family, ok := tags["family"]
	if ok { // Family will not be present if using tcp_set_state
		if family != familyInet {
			return nil, errIrrelevantEvent
		}
	}

	protocol, ok := tags["protocol"]
	if ok { // Protocol will not be present if using tcp_set_state
		if protocol != protocolTCP {
			return nil, errIrrelevantEvent
		}
	}

	sPort, ok := tags["sport"]
	if !ok {
		return nil, errors.New("source port not present in event")
	}
	sourcePort, err := strconv.ParseUint(sPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("converting source port to integer: %w", err)
	}

	dPort, ok := tags["dport"]
	if !ok {
		return nil, errors.New("destination port not present in event")
	}
	destPort, err := strconv.ParseUint(dPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("converting destination port to integer: %w", err)
	}

	sAddr, ok := tags["saddr"]
	if !ok {
		return nil, errors.New("source address not present in event")
	}
	sourceIP := net.ParseIP(sAddr)
	if sourceIP == nil {
		return nil, errors.New("could not parse source address")
	}

	dAddr, ok := tags["daddr"]
	if !ok {
		return nil, errors.New("destination address not present in event")
	}
	destIP := net.ParseIP(dAddr)
	if destIP == nil {
		return nil, errors.New("could not parse destination address")
	}

	/* 	sAddrV6, ok := tags["saddrv6"]
	   	if !ok {
	   		return nil, errors.New("source IPv6 address not present in event")
	   	}

	   	dAddrV6, ok := tags["daddrv6"]
	   	if !ok {
	   		return nil, errors.New("destination IPv6 address not present in event")
	   	} */

	oldState, ok := tags["oldstate"]
	if !ok {
		return nil, errors.New("old state not present in event")
	}
	canonicalOldState, err := canonicaliseState(oldState)
	if err != nil {
		return nil, fmt.Errorf("canonicalising old state: %w", err)
	}

	newState, ok := tags["newstate"]
	if !ok {
		return nil, errors.New("new state not present in event")
	}
	canonicalNewState, err := canonicaliseState(newState)
	if err != nil {
		return nil, fmt.Errorf("canonicalising new state: %w", err)
	}

	return &event.Event{
		Time:         time,
		CommandOnCPU: command,
		PIDOnCPU:     int(pid),
		SourceIP:     sourceIP,
		DestIP:       destIP,
		SourcePort:   uint16(sourcePort),
		DestPort:     uint16(destPort),
		OldState:     canonicalOldState,
		NewState:     canonicalNewState,
	}, nil
}

func canonicaliseState(state string) (tcpstate.State, error) {
	switch state {
	case "TCP_CLOSE":
		state = "CLOSED"
	case "TCP_FIN_WAIT1":
		state = "FIN-WAIT-1"
	case "TCP_FIN_WAIT2":
		state = "FIN-WAIT-2"
	case "TCP_SYN_RECV":
		state = "SYN-RECEIVED"
	default:
		state = strings.TrimPrefix(state, "TCP_")
		state = strings.ReplaceAll(state, "_", "-")
	}

	return tcpstate.FromString(state)
}

func parseCommand(str *[]byte) (command string, err error) {
	defer panicToErr("parsing next field", &err) // Catch any unexpected slicing errors without panicking

	// Get index of colon, then work backwards to the last dash.
	// This is needed as the command is delimited by a dash, but may contain a dash itself!
	idx := bytes.Index(*str, colonSpaceBytes)
	if idx == -1 { // No ': ' present
		return "", io.ErrUnexpectedEOF
	}

	for ; (*str)[idx] != byte('-') && idx > 0; idx-- {
	}

	if idx == 0 { // No command present
		return "", io.ErrUnexpectedEOF
	}

	cmd := (*str)[:idx]
	*str = (*str)[idx+1:]

	// Strip leading padding spaces
	for idx = 0; cmd[idx] == byte(' '); idx++ {
	}
	command = string(cmd[idx:])

	return command, nil
}
