package main

import (
	"log"
	"net"

	"github.com/ltcsuite/ltcd/wire"
	"github.com/miekg/dns"
)

// serviceDef defines a DNS subdomain prefix and the required service flags.
type serviceDef struct {
	prefix string
	flags  []wire.ServiceFlag
}

var serviceDefs = []serviceDef{
	// (none)
	// std: no special services required
	{"", []wire.ServiceFlag{}},
	// NETWORK
	{"x1", []wire.ServiceFlag{wire.SFNodeNetwork}},
	// NETWORK | GETUTXO
	{"x3", []wire.ServiceFlag{wire.SFNodeNetwork, 2}},
	// NETWORK | BLOOM
	{"x5", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeBloom}},
	// NETWORK | WITNESS
	{"x9", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeWitness}},
	// NETWORK | BLOOM | WITNESS
	{"xd", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeBloom, wire.SFNodeWitness}},
	// NETWORK | COMPACT_FILTERS
	{"x41", []wire.ServiceFlag{wire.SFNodeNetwork, 64}},
	// NETWORK | WITNESS | COMPACT_FILTERS
	{"x49", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeWitness, 64}},
	// NETWORK_LIMITED
	{"x400", []wire.ServiceFlag{1024}},
	// NETWORK_LIMITED | GETUTXO
	{"x403", []wire.ServiceFlag{1024, 2}},
	// NETWORK_LIMITED | BLOOM
	{"x404", []wire.ServiceFlag{1024, wire.SFNodeBloom}},
	// NETWORK_LIMITED | WITNESS
	{"x408", []wire.ServiceFlag{1024, wire.SFNodeWitness}},
	// NETWORK_LIMITED | BLOOM | WITNESS
	{"x40c", []wire.ServiceFlag{1024, wire.SFNodeBloom, wire.SFNodeWitness}},
	// NETWORK_LIMITED | COMPACT_FILTERS
	{"x440", []wire.ServiceFlag{1024, 64}},
	// NETWORK_LIMITED | WITNESS | COMPACT_FILTERS
	{"x448", []wire.ServiceFlag{1024, wire.SFNodeWitness, 64}},
	// NETWORK | WITNESS | MWEB
	{"x1000009", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeWitness, 16777216}},
	// NETWORK | WITNESS | COMPACT_FILTERS | MWEB
	{"x1000049", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeWitness, 64, 16777216}},
	// NETWORK_LIMITED | WITNESS | MWEB
	{"x1000408", []wire.ServiceFlag{1024, wire.SFNodeWitness, 16777216}},
	// NETWORK_LIMITED | WITNESS | COMPACT_FILTERS | MWEB
	{"x1000448", []wire.ServiceFlag{1024, wire.SFNodeWitness, 64, 16777216}},
	// NETWORK | WITNESS | COMPACT_FILTERS | MWEB | MWEB_LIGHT_CLIENT
	{"x1800049", []wire.ServiceFlag{wire.SFNodeNetwork, wire.SFNodeWitness, 64, 16777216, 8388608}},
	// NETWORK_LIMITED | WITNESS | COMPACT_FILTERS | MWEB | MWEB_LIGHT_CLIENT
	{"x1800448", []wire.ServiceFlag{1024, wire.SFNodeWitness, 64, 16777216, 8388608}},
}

// updateDNS builds and publishes DNS records for a seeder.
func (s *dnsseeder) updateDNS() {
	records := make(map[string][]dns.RR)

	// Collect both A and AAAA records based on nd.dnsType
	// and register both "x" and "0x" prefix variants
	s.mtx.RLock()
	for _, nd := range s.theList {
		if nd.status != statusCG {
			continue
		}

		// Determine record type
		var recType uint16
		switch nd.dnsType {
		case dnsV4Std:
			recType = dns.TypeA
		case dnsV6Std:
			recType = dns.TypeAAAA
		default:
			continue
		}

		// Iterate service definitions
		for _, def := range serviceDefs {
			if !hasAllFlags(nd.services, def.flags...) {
				continue
			}

			// Build both plain and "0x" prefixed subdomains
			prefixes := []string{def.prefix}
			if def.prefix != "" {
				prefixes = append(prefixes, "0"+def.prefix)
			}

			// Append records for each prefix variant
			for _, pref := range prefixes {
				addRecord(records, pref, s.dnsHost, nd.na.IP, recType, s.ttl)
			}
		}
	}
	s.mtx.RUnlock()

	if config.debug {
		for key, slice := range records {
			log.Printf("debug - %s: %d records", key, len(slice))
		}
	}

	// Publish updated records
	config.dnsmtx.Lock()
	for key, slice := range records {
		config.dns[key] = slice
	}
	config.dnsmtx.Unlock()
}

// updateDNS is a compatibility wrapper.
func updateDNS(s *dnsseeder) {
	s.updateDNS()
}

// hasAllFlags checks if svc contains all provided flags.
func hasAllFlags(svc wire.ServiceFlag, flags ...wire.ServiceFlag) bool {
	for _, f := range flags {
		if svc&f == 0 {
			return false
		}
	}
	return true
}

// addRecord appends an A or AAAA record under records map.
func addRecord(records map[string][]dns.RR, prefix, host string, ip net.IP, recordType uint16, ttl uint32) {
	name := host + "."
	if prefix != "" {
		name = prefix + "." + host + "."
	}
	var rr dns.RR
	switch recordType {
	case dns.TypeA:
		rec := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}}
		rec.A = ip
		rr = rec
	case dns.TypeAAAA:
		rec := &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}}
		rec.AAAA = ip
		rr = rec
	default:
		return
	}
	recordKey := name + recordSuffix(recordType)
	records[recordKey] = append(records[recordKey], rr)
}

// recordSuffix returns the DNS type suffix for map keys.
func recordSuffix(t uint16) string {
	switch t {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	}
	return ""
}

// handleDNS answers incoming DNS queries.
func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true, RecursionAvailable: false}}
	resp.SetReply(r)

	q := r.Question[0]
	resp.Answer = lookupRecords(q.Name, q.Qtype)
	w.WriteMsg(resp)
	// record stats async
	go updateDNSCounts(q.Name, qtypeString(q.Qtype))
}

// lookupRecords fetches cached DNS records or returns empty slice.
// lookupRecords fetches cached DNS records or returns empty slice.
func lookupRecords(name string, qtype uint16) []dns.RR {
	key := name + qtypeString(qtype)
	config.dnsmtx.RLock()
	defer config.dnsmtx.RUnlock()
	return config.dns[key]
}

func qtypeString(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeMX:
		return "MX"
	case dns.TypeNS:
		return "NS"
	}
	return "UNKNOWN"
}

// serve starts a DNS server on the given network and port.
func serve(network, port string) {
	server := &dns.Server{Addr: ":" + port, Net: network}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("failed to setup %s server: %v", network, err)
	}
}
