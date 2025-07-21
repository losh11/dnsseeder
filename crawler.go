package main

import (
	"errors"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/peer"
	"github.com/ltcsuite/ltcd/wire"
)

type crawlError struct {
	errLoc string
	Err    error
}

// Error returns a formatted error about a crawl
func (e *crawlError) Error() string {
	return "err: " + e.errLoc + ": " + e.Err.Error()
}

// crawlNode runs in a goroutine, crawls the remote ip and updates the master
// list of currently active addresses
func crawlNode(rc chan *result, s *dnsseeder, nd *node) {

	res := &result{
		node: net.JoinHostPort(nd.na.IP.String(), strconv.Itoa(int(nd.na.Port))),
	}

	// connect to the remote ip and ask them for their addr list
	res.nas, res.msg = crawlIP(s, res)

	// all done so push the result back to the seeder.
	//This will block until the seeder reads the result
	rc <- res

	// goroutine will end and be cleaned up
}

// crawlIP retrievs a slice of ip addresses from a client
func crawlIP(s *dnsseeder, r *result) ([]*wire.NetAddress, *crawlError) {
	// use ltcd to attempt connection to Peer
	verack := make(chan struct{})
	onAddr := make(chan *wire.MsgAddr)
	peerCfg := &peer.Config{
		UserAgentName: "ltcseeder",
		Services:      0,
		Listeners: peer.MessageListeners{
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				if config.debug {
					log.Printf("%s - debug - %s - Remote version: %v\n", s.name, r.node, msg.ProtocolVersion)
				}
				// fill the node struct with the remote details
				r.version = msg.ProtocolVersion
				r.services = msg.Services
				r.lastBlock = msg.LastBlock
				r.strVersion = msg.UserAgent
				return nil
			},
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
			OnAddr: func(p *peer.Peer, msg *wire.MsgAddr) {
				onAddr <- msg
			},
		},
	}

	if s.port == 9333 {
		peerCfg.ChainParams = &chaincfg.MainNetParams
	} else {
		peerCfg.ChainParams = &chaincfg.TestNet4Params
	}

	// Create and start the outbound peer
	p, err := peer.NewOutboundPeer(peerCfg, r.node)
	if err != nil {
		return nil, &crawlError{"NewOutboundPeer: error", err}
	}

	// Establish the connection to the peer address and mark it connected.
	// Use appropriate network type for IPv4/IPv6 based on the peer address
	network := "tcp"
	peerHost, _, err := net.SplitHostPort(p.Addr())
	if err == nil {
		if net.ParseIP(peerHost).To4() == nil {
			// IPv6 address
			network = "tcp6"
		} else {
			// IPv4 address  
			network = "tcp4"
		}
	}
	
	conn, err := net.Dial(network, p.Addr())
	if err != nil {
		return nil, &crawlError{"net.Dial: error", err}
	}
	p.AssociateConnection(conn)

	defer p.WaitForDisconnect()
	defer p.Disconnect()

	// check verack
	select {
	case <-verack:
	case <-time.After(time.Second * 3):
		return nil, &crawlError{"verack timeout", errors.New("")}
	}

	// if we get this far and if the seeder is full then don't ask for addresses. This will reduce bandwith usage while still
	// confirming that we can connect to the remote node
	s.mtx.RLock()
	if len(s.theList) > s.maxSize {
		return nil, nil
	}
	s.mtx.RUnlock()

	p.QueueMessage(wire.NewMsgGetAddr(), nil)

	addrMsg := new(wire.MsgAddr)
	select {
	case addrMsg = <-onAddr:
	case <-time.After(time.Second * 6):
	}

	return addrMsg.AddrList, nil
}
