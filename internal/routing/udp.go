package routing

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
)

const (
	udpIdleTimeout = 60 * time.Second
)

type udpSession struct {
	conn       *net.UDPConn
	lastActive time.Time
	srcIP      netip.Addr
	dstIP      netip.Addr
	srcPort    uint16
	dstPort    uint16
}

type UDPForwarder struct {
	protect  func(fd int) bool
	tunDev   tun.Device
	sessions map[string]*udpSession
	mu       sync.Mutex
	closed   bool
	logger   logx.Logger
}

func NewUDPForwarder(tunDev tun.Device, protect func(fd int) bool, logger logx.Logger) *UDPForwarder {
	f := &UDPForwarder{
		protect:  protect,
		tunDev:   tunDev,
		sessions: make(map[string]*udpSession),
		logger:   logx.OrNop(logger),
	}
	go f.cleanupLoop()
	return f
}

func (f *UDPForwarder) HandlePacket(pkt ParsedPacket) {
	key := fmt.Sprintf("%s:%d->%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	sess, exists := f.sessions[key]
	if !exists {
		conn, err := f.dial(pkt.DstIP, pkt.DstPort)
		if err != nil {
			f.mu.Unlock()
			f.logger.Warnf("udp forwarder: dial %s:%d failed: %v", pkt.DstIP, pkt.DstPort, err)
			return
		}
		sess = &udpSession{
			conn:       conn,
			lastActive: time.Now(),
			srcIP:      pkt.SrcIP,
			dstIP:      pkt.DstIP,
			srcPort:    pkt.SrcPort,
			dstPort:    pkt.DstPort,
		}
		f.sessions[key] = sess
		go f.readResponses(key, sess)
	}
	sess.lastActive = time.Now()
	f.mu.Unlock()

	if _, err := sess.conn.Write(pkt.Payload); err != nil {
		f.logger.Warnf("udp forwarder: write to %s:%d: %v", pkt.DstIP, pkt.DstPort, err)
	}
}

func (f *UDPForwarder) dial(dstIP netip.Addr, dstPort uint16) (*net.UDPConn, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: makeControl(f.protect),
	}

	targetAddr := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))
	conn, err := dialer.DialContext(context.Background(), "udp", targetAddr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("expected *net.UDPConn, got %T", conn)
	}
	return udpConn, nil
}

func (f *UDPForwarder) readResponses(key string, sess *udpSession) {
	buf := make([]byte, 4096)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := sess.conn.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			f.mu.Lock()
			sess.lastActive = time.Now()
			f.mu.Unlock()

			respPkt := BuildIPv4UDP(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, buf[:n])
			_, _ = f.tunDev.Write([][]byte{respPkt}, 0)
		}
	}

	f.mu.Lock()
	if f.sessions[key] == sess {
		delete(f.sessions, key)
	}
	f.mu.Unlock()
	_ = sess.conn.Close()
}

func (f *UDPForwarder) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return
		}
		now := time.Now()
		for k, sess := range f.sessions {
			if now.Sub(sess.lastActive) > udpIdleTimeout {
				_ = sess.conn.Close()
				delete(f.sessions, k)
			}
		}
		f.mu.Unlock()
	}
}

func (f *UDPForwarder) Close() {
	f.mu.Lock()
	f.closed = true
	for _, s := range f.sessions {
		_ = s.conn.Close()
	}
	clear(f.sessions)
	f.mu.Unlock()
}
