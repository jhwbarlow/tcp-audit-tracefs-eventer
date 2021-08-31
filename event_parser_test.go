package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	// TODO: Check event struct fields are correct/match the input!
}

func TestParseIrrelevantEventErrorOnNonInetAddressFamily(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_UNIX")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if err != errIrrelevantEvent {
		t.Errorf("expected error to be %q, but was %q", errIrrelevantEvent, err)
	}
}

func TestParseIrrelevantEventErrorOnNonTCPProtocol(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_FOO")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if err != errIrrelevantEvent {
		t.Errorf("expected error to be %q, but was %q", errIrrelevantEvent, err)
	}
}

func TestParseErrorNoCommandSeparator(t *testing.T) {
	mockEventTrace := []byte("<idle>0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected error chain to include %q, but did not", io.ErrUnexpectedEOF)
	}
}

func TestParseErrorNoColonSpaceSeparator(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985 inet_sock_set_state family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected error chain to include %q, but did not", io.ErrUnexpectedEOF)
	}
}

func TestParseErrorNoPIDSeparator(t *testing.T) {
	mockEventTrace := []byte("<idle>-0: ")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "PID") {
		t.Errorf("expected error string to contain %q, but did not", "PID")
	}
}

func TestParseErrorNonIntegerPID(t *testing.T) {
	mockEventTrace := []byte("<idle>-foo       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "PID") {
		t.Errorf("expected error string to contain %q, but did not", "PID")
	}
}

func TestParseErrorNoSrcPortTag(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "source port") {
		t.Errorf("expected error string to contain %q, but did not", "source port")
	}
}

func TestParseErrorNoDstPortTag(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "destination port") {
		t.Errorf("expected error string to contain %q, but did not", "destination port")
	}
}

func TestParseErrorNoSrcAddrTag(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "source address") {
		t.Errorf("expected error string to contain %q, but did not", "source address")
	}
}

func TestParseErrorNoDstAddrTag(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "destination address") {
		t.Errorf("expected error string to contain %q, but did not", "destination address")
	}
}

func TestParseErrorNoOldStateAddrTag(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "old state") {
		t.Errorf("expected error string to contain %q, but did not", "old state")
	}
}

func TestParseErrorNoNewStateAddrTag(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "new state") {
		t.Errorf("expected error string to contain %q, but did not", "new state")
	}
}

func TestParseErrorNonIntegerSrcPort(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=foo dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "source port") {
		t.Errorf("expected error string to contain %q, but did not", "source port")
	}
}

func TestParseErrorNonIntegerDstPort(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=1234 dport=foo saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "destination port") {
		t.Errorf("expected error string to contain %q, but did not", "destination port")
	}
}

func TestParseErrorInvalidSrcAddr(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=1234 dport=80 saddr=foo daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "source address") {
		t.Errorf("expected error string to contain %q, but did not", "source address")
	}
}

func TestParseErrorInvalidDstAddr(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=1234 dport=80 saddr=172.217.169.4 daddr=foo saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "destination address") {
		t.Errorf("expected error string to contain %q, but did not", "destination address")
	}
}

func TestParseErrorInvalidOldState(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=FOO_BAR newstate=TCP_ESTABLISHED")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "old state") {
		t.Errorf("expected error string to contain %q, but did not", "old state")
	}
}

func TestParseErrorInvalidNewState(t *testing.T) {
	mockEventTrace := []byte("<idle>-0       [000] ..s.   995.318985: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=44406 dport=80 saddr=192.168.122.38 daddr=172.217.169.4 saddrv6=::ffff:192.168.122.38 daddrv6=::ffff:172.217.169.4 oldstate=TCP_ESTABLISHED newstate=FOO_BAR")
	fieldParser := new(slicingFieldParser)
	eventParser := newTraceFSEventParser(fieldParser)
	_, err := eventParser.toEvent(mockEventTrace)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !strings.Contains(err.Error(), "new state") {
		t.Errorf("expected error string to contain %q, but did not", "new state")
	}
}
