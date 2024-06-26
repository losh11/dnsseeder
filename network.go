package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ltcsuite/ltcd/wire"
)

// JNetwork is the exported struct that is read from the network file
type JNetwork struct {
	Name       string
	Desc       string
	ID         string
	Port       uint16
	Pver       uint32
	DNSName    string
	TTL        uint32
	InitialIPs []string
	Seeders    []string
}

func loadNetwork(fName string) (*dnsseeder, error) {
	nwFile, err := os.Open(fName)
	if err != nil {
		return nil, fmt.Errorf("error reading network file: %v", err)
	}

	defer nwFile.Close()

	var jnw JNetwork

	jsonParser := json.NewDecoder(nwFile)
	if err = jsonParser.Decode(&jnw); err != nil {
		return nil, fmt.Errorf("error decoding network file: %v", err)
	}

	return initNetwork(jnw)
}

func initNetwork(jnw JNetwork) (*dnsseeder, error) {

	if jnw.Port == 0 {
		return nil, fmt.Errorf("invalid port supplied: %v", jnw.Port)

	}

	if jnw.DNSName == "" {
		return nil, fmt.Errorf("no dns hostname supplied")
	}

	// init the seeder
	seeder := &dnsseeder{}
	seeder.theList = make(map[string]*node)
	seeder.port = jnw.Port
	seeder.pver = jnw.Pver
	seeder.ttl = jnw.TTL
	seeder.name = jnw.Name
	seeder.desc = jnw.Desc
	seeder.dnsHost = jnw.DNSName

	// conver the network magic number to a Uint32
	t1, err := strconv.ParseUint(jnw.ID, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("Error converting Network Magic number: %v", err)
	}
	seeder.id = wire.BitcoinNet(t1)

	seeder.initialIPs = jnw.InitialIPs

	// load the seeder dns
	seeder.seeders = jnw.Seeders

	// add some checks to the start & delay values to keep them sane
	seeder.maxStart = []uint32{20, 20, 20, 30}
	seeder.delay = []int64{210, 789, 234, 1876}
	seeder.maxSize = 1250

	// initialize the stats counters
	seeder.counts.NdStatus = make([]uint32, maxStatusTypes)
	seeder.counts.NdStarts = make([]uint32, maxStatusTypes)
	seeder.counts.DNSCounts = make([]uint32, maxDNSTypes)

	// some sanity checks on the loaded config options
	if seeder.ttl < 60 {
		seeder.ttl = 60
	}

	if dup, err := isDuplicateSeeder(seeder); dup {
		return nil, err
	}

	return seeder, nil
}
