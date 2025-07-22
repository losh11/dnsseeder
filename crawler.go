package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/peer"
	"github.com/ltcsuite/ltcd/wire"
)

const (
	dialTimeout       = 10 * time.Second
	peerAddrTimeout   = 6 * time.Second
	verAckTimeout     = 3 * time.Second
	manualMsgLimit    = 20
	manualConnTimeout = 10 * time.Second
	maxAddrMessages   = 50
)

type crawlError struct {
	loc string
	err error
}

func (e *crawlError) Error() string {
	return fmt.Sprintf("crawl error at %s: %v", e.loc, e.err)
}

func crawlNode(rc chan<- *result, s *dnsseeder, nd *node) {
	addr := net.JoinHostPort(nd.na.IP.String(), strconv.Itoa(int(nd.na.Port)))
	res := &result{node: addr}

	peers, cerr := crawlIP(s, res)
	if cerr != nil {
		res.msg = cerr
	}
	res.nas = peers
	rc <- res
}

// crawlIP attempts to fetch addresses via ltcd Peer handshake, falling back to manual wire protocol.
func crawlIP(s *dnsseeder, r *result) ([]*wire.NetAddress, *crawlError) {
	if peers, ok := fetchViaPeer(s, r); ok {
		return peers, nil
	}
	return fetchViaManual(s, r)
}

// fetchViaPeer tries the newer ltcd Peer abstraction.
func fetchViaPeer(s *dnsseeder, r *result) ([]*wire.NetAddress, bool) {
	verack := make(chan struct{}, 1)
	addrCh := make(chan []*wire.NetAddress, 1)

	cfg := &peer.Config{
		UserAgentName: "ltcseeder",
		Services:      0,
		Listeners: peer.MessageListeners{
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				debugLog(s.name, "version", r.node, fmt.Errorf("protocol %d", msg.ProtocolVersion))
				r.version, r.services, r.lastBlock, r.strVersion =
					msg.ProtocolVersion, msg.Services, msg.LastBlock, msg.UserAgent
				return nil
			},
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
			OnAddr: func(p *peer.Peer, msg *wire.MsgAddr) {
				select {
				case addrCh <- msg.AddrList:
				default:
				}
			},
		},
	}
	if s.port == 9333 {
		cfg.ChainParams = &chaincfg.MainNetParams
	} else {
		cfg.ChainParams = &chaincfg.TestNet4Params
	}

	p, err := peer.NewOutboundPeer(cfg, r.node)
	if err != nil {
		return nil, false
	}
	defer p.WaitForDisconnect()
	defer p.Disconnect()

	network := dialNetwork(p.Addr())
	conn, err := net.Dial(network, p.Addr())
	if err != nil {
		return nil, false
	}
	p.AssociateConnection(conn)

	select {
	case <-verack:
	case <-time.After(verAckTimeout):
		return nil, false
	}

	p.QueueMessage(wire.NewMsgGetAddr(), nil)

	select {
	case addrs := <-addrCh:
		debugLog(s.name, "addr", r.node, fmt.Errorf("%d peers", len(addrs)))
		if len(addrs) > 0 {
			return addrs, true
		}
	case <-time.After(peerAddrTimeout):
		debugLog(s.name, "addr timeout", r.node, nil)
	}
	return nil, false
}

// fetchViaManual falls back to raw wire protocol for legacy nodes.
func fetchViaManual(s *dnsseeder, r *result) ([]*wire.NetAddress, *crawlError) {
	ctx, cancel := context.WithTimeout(context.Background(), manualConnTimeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", r.node)
	if err != nil {
		debugLog(s.name, "manual dial", r.node, err)
		return nil, &crawlError{"manual dial", err}
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(ioDeadline())); err != nil {
		return nil, &crawlError{"set deadline", err}
	}

	me := wire.NewNetAddress(conn.LocalAddr().(*net.TCPAddr), wire.SFNodeNetwork)
	you := wire.NewNetAddress(conn.RemoteAddr().(*net.TCPAddr), wire.SFNodeNetwork)

	// handshake
	if err := wire.WriteMessage(conn, wire.NewMsgVersion(me, you, nounce, 0), s.pver, s.id); err != nil {
		return nil, &crawlError{"write version", err}
	}
	msg, _, err := wire.ReadMessage(conn, s.pver, s.id)
	if err != nil {
		return nil, &crawlError{"read version", err}
	}
	if _, ok := msg.(*wire.MsgVersion); !ok {
		return nil, &crawlError{"version type", fmt.Errorf("%T", msg)}
	}

	if err := wire.WriteMessage(conn, wire.NewMsgVerAck(), s.pver, s.id); err != nil {
		return nil, &crawlError{"write verack", err}
	}

	if err := waitForVerAck(conn, s, r); err != nil {
		return nil, err
	}

	if err := wire.WriteMessage(conn, wire.NewMsgGetAddr(), s.pver, s.id); err != nil {
		return nil, &crawlError{"write getaddr", err}
	}

	peers := collectAddrs(conn, s, r)
	if len(peers) > 0 {
		return peers, nil
	}
	return nil, &crawlError{"no addrs", fmt.Errorf("no peers after manual fetch")}
}

func waitForVerAck(conn net.Conn, s *dnsseeder, r *result) *crawlError {
	for i := 0; i < manualMsgLimit; i++ {
		msg, _, err := wire.ReadMessage(conn, s.pver, s.id)
		if err != nil {
			continue
		}
		if _, ok := msg.(*wire.MsgVerAck); ok {
			return nil
		}
	}
	return &crawlError{"verack wait", fmt.Errorf("verack not received in %d msgs", manualMsgLimit)}
}

func collectAddrs(conn net.Conn, s *dnsseeder, r *result) []*wire.NetAddress {
	var peers []*wire.NetAddress
	for i := 0; i < maxAddrMessages; i++ {
		msg, _, err := wire.ReadMessage(conn, s.pver, s.id)
		if err != nil {
			continue
		}
		if addrMsg, ok := msg.(*wire.MsgAddr); ok {
			debugLog(s.name, "addr", r.node, fmt.Errorf("%d peers", len(addrMsg.AddrList)))
			peers = append(peers, addrMsg.AddrList...)
			if len(peers) > 1 {
				break
			}
		}
	}
	return peers
}

func dialNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	if net.ParseIP(host).To4() == nil {
		return "tcp6"
	}
	return "tcp4"
}

func ioDeadline() time.Duration {
	return time.Second * maxTo
}

func debugLog(nodeName, phase, addr string, info error) {
	if config.debug {
		if info != nil {
			log.Printf("%s - debug - %s - %s: %v\n", nodeName, phase, addr, info)
		} else {
			log.Printf("%s - debug - %s - %s\n", nodeName, phase, addr)
		}
	}
}
