package main

import (
	"net"
	"strconv"
	"testing"

	"github.com/ltcsuite/ltcd/wire"
)

func TestAddnNa(t *testing.T) {
	// create test data struct
	var td = []struct {
		ip      string
		port    int
		dnsType uint32
	}{
		{"1.2.3.4", 29333, 1},
		{"50.123.45.67", 43210, 2},
	}

	s := &dnsseeder{
		port:    29333,
		pver:    1234,
		maxSize: 1,
	}
	s.theList = make(map[string]*node)

	for _, atest := range td {
		// Test NewNetAddress.
		tcpAddr := &net.TCPAddr{
			IP:   net.ParseIP(atest.ip),
			Port: atest.port,
		}
		na := wire.NewNetAddress(tcpAddr, 0)
		ndName := net.JoinHostPort(na.IP.String(), strconv.Itoa(int(na.Port)))

		result := s.addNa(na)
		if result != true {
			t.Errorf("failed to create new node: %s", ndName)
		}
	}

	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1234,
	}
	na := wire.NewNetAddress(tcpAddr, 0)
	result := s.addNa(na)

	if result != false {
		t.Errorf("node added but should have failed as seeder full: %s", net.JoinHostPort(na.IP.String(), strconv.Itoa(int(na.Port))))
	}

	tcpAddr = &net.TCPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 29333,
	}
	na = wire.NewNetAddress(tcpAddr, 0)
	result = s.addNa(na)

	if result != false {
		t.Errorf("node added but should have failed as duplicate: %s", net.JoinHostPort(na.IP.String(), strconv.Itoa(int(na.Port))))
	}

}
