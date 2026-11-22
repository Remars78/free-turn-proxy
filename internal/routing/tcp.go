package routing

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
)

const (
	tcpConnectTimeout = 10 * time.Second
	tcpIdleTimeout    = 90 * time.Second
	defaultMSS        = 1240 // 1280 (WG MTU) - 20 (IP) - 20 (TCP)
)

type tcpState int

const (
	tcpStateSynReceived tcpState = iota
	tcpStateEstablished
	tcpStateFinWait
	tcpStateClosed
)

type tcpSession struct {
	key        string
	conn       net.Conn
	srcIP      netip.Addr
	dstIP      netip.Addr
	srcPort    uint16
	dstPort    uint16
	state      tcpState
	mu         sync.Mutex
	lastActive time.Time

	clientISN uint32
	clientSeq uint32
	ourISN    uint32
	ourSeq    uint32

	closed atomic.Bool
}

type TCPForwarder struct {
	protect  func(fd int) bool
	tunDev   tun.Device
	sessions map[string]*tcpSession
	mu       sync.Mutex
	closed   bool
	logger   logx.Logger
}

func NewTCPForwarder(tunDev tun.Device, protect func(fd int) bool, logger logx.Logger) *TCPForwarder {
	f := &TCPForwarder{
		protect:  protect,
		tunDev:   tunDev,
		sessions: make(map[string]*tcpSession),
		logger:   logx.OrNop(logger),
	}
	go f.cleanupLoop()
	return f
}

func (f *TCPForwarder) HandlePacket(pkt ParsedPacket) {
	key := fmt.Sprintf("%s:%d->%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	if pkt.TCPFlags&TCPFlagSYN != 0 && pkt.TCPFlags&TCPFlagACK == 0 {
		f.handleSyn(key, pkt)
		return
	}

	f.mu.Lock()
	sess, exists := f.sessions[key]
	f.mu.Unlock()

	if !exists || sess.closed.Load() {
		if pkt.TCPFlags&TCPFlagRST == 0 {
			f.sendRst(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, pkt.AckNum, pkt.SeqNum+uint32(len(pkt.Payload)))
		}
		return
	}

	sess.mu.Lock()
	sess.lastActive = time.Now()

	if pkt.TCPFlags&TCPFlagRST != 0 {
		sess.state = tcpStateClosed
		sess.closed.Store(true)
		if sess.conn != nil {
			_ = sess.conn.Close()
		}
		sess.mu.Unlock()
		f.removeSession(key)
		return
	}

	if pkt.TCPFlags&TCPFlagFIN != 0 {
		sess.clientSeq = pkt.SeqNum + 1
		sess.state = tcpStateClosed
		sess.closed.Store(true)
		ackPkt := BuildIPv4TCP(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, sess.ourSeq, sess.clientSeq, TCPFlagACK, 65535, nil)
		_, _ = f.tunDev.Write([][]byte{ackPkt}, 0)
		if sess.conn != nil {
			_ = sess.conn.Close()
		}
		sess.mu.Unlock()
		f.removeSession(key)
		return
	}

	if sess.state == tcpStateSynReceived && pkt.TCPFlags&TCPFlagACK != 0 {
		sess.state = tcpStateEstablished
		sess.clientSeq = pkt.SeqNum
	}

	payloadLen := len(pkt.Payload)
	if payloadLen > 0 && sess.conn != nil {
		sess.clientSeq = pkt.SeqNum + uint32(payloadLen)
		_, err := sess.conn.Write(pkt.Payload)
		if err != nil {
			f.logger.Warnf("tcp forwarder: write to %s: %v", key, err)
			sess.mu.Unlock()
			f.sendRst(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, sess.ourSeq, sess.clientSeq)
			f.removeSession(key)
			return
		}
		ackPkt := BuildIPv4TCP(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, sess.ourSeq, sess.clientSeq, TCPFlagACK, 65535, nil)
		_, _ = f.tunDev.Write([][]byte{ackPkt}, 0)
	}

	sess.mu.Unlock()
}

func (f *TCPForwarder) handleSyn(key string, pkt ParsedPacket) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}

	if existing, ok := f.sessions[key]; ok && !existing.closed.Load() {
		// Повторный SYN при задержке хендшейка: если сокет уже открыт, отправляем SYN-ACK повторно
		existing.mu.Lock()
		if existing.conn != nil {
			synAck := BuildIPv4TCPSynAck(existing.dstIP, existing.srcIP, existing.dstPort, existing.srcPort, existing.ourISN, existing.clientSeq, defaultMSS)
			_, _ = f.tunDev.Write([][]byte{synAck}, 0)
		}
		existing.mu.Unlock()
		f.mu.Unlock()
		return
	}

	var ourISN uint32
	var b [4]byte
	_, _ = rand.Read(b[:])
	ourISN = binary.BigEndian.Uint32(b[:])

	sess := &tcpSession{
		key:        key,
		srcIP:      pkt.SrcIP,
		dstIP:      pkt.DstIP,
		srcPort:    pkt.SrcPort,
		dstPort:    pkt.DstPort,
		state:      tcpStateSynReceived,
		lastActive: time.Now(),
		clientISN:  pkt.SeqNum,
		clientSeq:  pkt.SeqNum + 1,
		ourISN:     ourISN,
		ourSeq:     ourISN + 1,
	}

	if old, ok := f.sessions[key]; ok {
		old.closed.Store(true)
		if old.conn != nil {
			_ = old.conn.Close()
		}
	}
	f.sessions[key] = sess
	f.mu.Unlock()

	go f.connectAndBridge(sess)
}

func (f *TCPForwarder) connectAndBridge(sess *tcpSession) {
	targetAddr := net.JoinHostPort(sess.dstIP.String(), fmt.Sprintf("%d", sess.dstPort))
	dialer := &net.Dialer{
		Timeout: tcpConnectTimeout,
		Control: makeControl(f.protect),
	}

	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		f.logger.Warnf("tcp forwarder: dial %s failed: %v", targetAddr, err)
		f.sendRst(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, sess.ourSeq, sess.clientSeq)
		f.removeSession(sess.key)
		return
	}

	sess.mu.Lock()
	if sess.closed.Load() {
		sess.mu.Unlock()
		_ = conn.Close()
		return
	}
	sess.conn = conn
	f.logger.Infof("tcp forwarder: direct session connected for %s", sess.key)
	sess.mu.Unlock()

	// Отправляем SYN-ACK с опцией MSS
	synAck := BuildIPv4TCPSynAck(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, sess.ourISN, sess.clientSeq, defaultMSS)
	_, _ = f.tunDev.Write([][]byte{synAck}, 0)

	buf := make([]byte, 16384)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		n, rerr := conn.Read(buf)
		if n > 0 {
			// Сегментируем ответ по MSS (1240 байт), чтобы размер IP-пакета не превышал MTU (1280)
			for offset := 0; offset < n; {
				chunkSize := n - offset
				if chunkSize > defaultMSS {
					chunkSize = defaultMSS
				}
				chunk := buf[offset : offset+chunkSize]
				offset += chunkSize

				flags := uint8(TCPFlagACK)
				if offset == n {
					flags |= TCPFlagPSH
				}

				sess.mu.Lock()
				sess.lastActive = time.Now()
				seq := sess.ourSeq
				ack := sess.clientSeq
				sess.ourSeq += uint32(chunkSize)
				sess.mu.Unlock()

				dataPkt := BuildIPv4TCP(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, seq, ack, flags, 65535, chunk)
				_, _ = f.tunDev.Write([][]byte{dataPkt}, 0)
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				sess.mu.Lock()
				seq := sess.ourSeq
				ack := sess.clientSeq
				sess.ourSeq++
				sess.state = tcpStateFinWait
				sess.mu.Unlock()

				finPkt := BuildIPv4TCP(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, seq, ack, TCPFlagFIN|TCPFlagACK, 65535, nil)
				_, _ = f.tunDev.Write([][]byte{finPkt}, 0)
			}
			break
		}
	}

	f.removeSession(sess.key)
	_ = conn.Close()
}

func (f *TCPForwarder) sendRst(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum, ackNum uint32) {
	rstPkt := BuildIPv4TCP(srcIP, dstIP, srcPort, dstPort, seqNum, ackNum, TCPFlagRST|TCPFlagACK, 0, nil)
	_, _ = f.tunDev.Write([][]byte{rstPkt}, 0)
}

func (f *TCPForwarder) removeSession(key string) {
	f.mu.Lock()
	delete(f.sessions, key)
	f.mu.Unlock()
}

func (f *TCPForwarder) cleanupLoop() {
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
			sess.mu.Lock()
			idle := now.Sub(sess.lastActive) > tcpIdleTimeout
			closed := sess.closed.Load()
			sess.mu.Unlock()

			if idle || closed {
				if sess.conn != nil {
					_ = sess.conn.Close()
				}
				delete(f.sessions, k)
			}
		}
		f.mu.Unlock()
	}
}

func (f *TCPForwarder) Close() {
	f.mu.Lock()
	f.closed = true
	for _, s := range f.sessions {
		s.closed.Store(true)
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
	clear(f.sessions)
	f.mu.Unlock()
}
