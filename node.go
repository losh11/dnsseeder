package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// Node struct contains details on one client
type node struct {
	na           *wire.NetAddress // holds ip address & port details
	lastConnect  time.Time        // last time we sucessfully connected to this client
	lastTry      time.Time        // last time we tried to connect to this client
	crawlStart   time.Time        // time when we started the last crawl
	nonstdIP     net.IP           // if not using the default port then this is the encoded ip containing the actual port
	statusStr    string           // string with last error or OK details
	strVersion   string           // remote client user agent
	services     wire.ServiceFlag // remote client supported services
	connectFails uint32           // number of times we have failed to connect to this client
	version      int32            // remote client protocol version
	lastBlock    int32            // remote client last block
	status       uint32           // rg,cg,wg,ng
	rating       uint32           // if it reaches 100 then we mark them statusNG
	dnsType      uint32           // what dns type this client is
	crawlActive  bool             // are we currently crawling this client
}

type serviceFlag uint64

const (
	x1       serviceFlag = 1<<0 + 1  // NODE_NETWORK
	x5       serviceFlag = 1<<2 + 1  // NODE_BLOOM
	x9       serviceFlag = 1<<3 + 1  // NODE_WITNESS
	x49      serviceFlag = 1<<6 + 1  // NODE_COMPACT_FILTERS
	x400     serviceFlag = 1<<10 + 1 // NODE_NETWORK_LIMITED
	x1000000 serviceFlag = 1<<24 + 1 // NODE_MWEB
)

// Map of service flags back to their constant names for pretty printing.
var sfStrings = map[serviceFlag]string{
	x1:       "NODE_NETWORK",
	x5:       "NODE_BLOOM",
	x9:       "NODE_WITNESS",
	x49:      "NODE_COMPACT_FILTERS",
	x400:     "NODE_NETWORK_LIMITED",
	x1000000: "NODE_MWEB",
}

// orderedSFStrings is an ordered list of service flags from highest to
// lowest.
var orderedSFStrings = []serviceFlag{
	x1,
	x5,
	x9,
	x49,
	x400,
	x1000000,
}

// String returns the ServiceFlag in human-readable form.
func (f serviceFlag) String() string {
	// No flags are set.
	if f == 0 {
		return "0x0"
	}

	// Add individual bit flags.
	s := ""
	for _, flag := range orderedSFStrings {
		if f&flag == flag {
			s += sfStrings[flag] + "|"
			f -= flag
		}
	}

	// Add any remaining flags which aren't accounted for as hex.
	s = strings.TrimRight(s, "|")
	if f != 0 {
		s += "|0x" + strconv.FormatUint(uint64(f), 16)
	}
	s = strings.TrimLeft(s, "|")
	return s
}

// dns2str will return the string description of the dns type
func (nd node) dns2str() string {
	switch nd.dnsType {
	case dnsV4Std:
		return "v4 standard port"
	case dnsV4Non:
		return "v4 non-standard port"
	case dnsV6Std:
		return "v6 standard port"
	case dnsV6Non:
		return "v6 non-standard port"
	default:
		return "Unknown DNS Type"
	}
}
