package routing

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/miekg/dns"
)

func TestZoneMatcher(t *testing.T) {
	zm := NewZoneMatcher([]string{"ru", "рф", "su"}, []string{"example.com", "api.service.org"})

	tests := []struct {
		domain   string
		expected bool
	}{
		{"sberbank.ru", true},
		{"sub.sberbank.ru", true},
		{"ru", true},
		{"gosuslugi.рф", true},
		{"sub.gosuslugi.xn--p1ai", true},
		{"site.su", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"api.service.org", true},
		{"google.com", false},
		{"notru.com", false},
		{"fake-ru.org", false},
		{"other.org", false},
		{"", false},
	}

	for _, tc := range tests {
		got := zm.IsBypassed(tc.domain)
		if got != tc.expected {
			t.Errorf("IsBypassed(%q) = %v; want %v", tc.domain, got, tc.expected)
		}
	}
}

func TestBypassCache(t *testing.T) {
	cache := NewBypassCache(10)
	ip1 := netip.MustParseAddr("192.168.1.1")
	ip2 := netip.MustParseAddr("192.168.1.2")

	if cache.Contains(ip1) {
		t.Fatalf("expected ip1 to not be in cache")
	}

	cache.Add(ip1, 100*time.Millisecond)
	if !cache.Contains(ip1) {
		t.Fatalf("expected ip1 to be in cache")
	}

	cache.Add(ip2, 2*time.Second)
	if !cache.Contains(ip2) {
		t.Fatalf("expected ip2 to be in cache")
	}

	time.Sleep(150 * time.Millisecond)
	if !cache.Contains(ip1) {
		t.Fatalf("expected ip1 to still be valid due to min TTL")
	}

	cache.Clear()
	if cache.Contains(ip1) || cache.Contains(ip2) {
		t.Fatalf("expected cache to be empty after Clear")
	}
}

func TestPacketParsingAndBuilding(t *testing.T) {
	src := netip.MustParseAddr("10.8.0.2")
	dst := netip.MustParseAddr("77.88.8.8")
	payload := []byte("hello dns query")

	udpPkt := BuildIPv4UDP(src, dst, 12345, 53, payload)
	parsed, ok := ParsePacket(udpPkt)
	if !ok {
		t.Fatalf("failed to parse built UDP packet")
	}
	if parsed.Protocol != ProtoUDP {
		t.Errorf("got protocol %d, want %d", parsed.Protocol, ProtoUDP)
	}
	if parsed.SrcPort != 12345 || parsed.DstPort != 53 {
		t.Errorf("got ports %d -> %d; want 12345 -> 53", parsed.SrcPort, parsed.DstPort)
	}
	if string(parsed.Payload) != string(payload) {
		t.Errorf("got payload %q; want %q", parsed.Payload, payload)
	}

	tcpPkt := BuildIPv4TCP(src, dst, 54321, 443, 1000, 2000, TCPFlagSYN, 65535, nil)
	parsedTCP, ok := ParsePacket(tcpPkt)
	if !ok {
		t.Fatalf("failed to parse built TCP packet")
	}
	if parsedTCP.Protocol != ProtoTCP {
		t.Errorf("got protocol %d, want %d", parsedTCP.Protocol, ProtoTCP)
	}
	if parsedTCP.TCPFlags&TCPFlagSYN == 0 {
		t.Errorf("expected SYN flag to be set")
	}
	if parsedTCP.SeqNum != 1000 || parsedTCP.AckNum != 2000 {
		t.Errorf("got seq=%d ack=%d; want seq=1000 ack=2000", parsedTCP.SeqNum, parsedTCP.AckNum)
	}
}

type mockTUN struct {
	readPackets  [][]byte
	writePackets [][]byte
}

func (*mockTUN) File() *os.File           { return nil }
func (*mockTUN) MTU() (int, error)        { return 1280, nil }
func (*mockTUN) Name() (string, error)    { return "mock", nil }
func (*mockTUN) Events() <-chan tun.Event { return nil }
func (*mockTUN) Close() error             { return nil }
func (*mockTUN) BatchSize() int           { return 1 }

func (m *mockTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(m.readPackets) == 0 {
		return 0, nil
	}
	pkt := m.readPackets[0]
	m.readPackets = m.readPackets[1:]
	copy(bufs[0][offset:], pkt)
	sizes[0] = len(pkt)
	return 1, nil
}

func (m *mockTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		cp := make([]byte, len(b)-offset)
		copy(cp, b[offset:])
		m.writePackets = append(m.writePackets, cp)
	}
	return len(bufs), nil
}

func TestTUNRouterPassthrough(t *testing.T) {
	mock := &mockTUN{
		readPackets: [][]byte{
			BuildIPv4UDP(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("1.1.1.1"), 1234, 443, []byte("data")),
		},
	}

	router := NewTUNRouter(mock, Config{
		BypassZones: []string{"ru", "рф"},
	})

	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 1500)
	sizes := make([]int, 1)

	n, err := router.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("router.Read failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 packet to pass through to WireGuard, got %d", n)
	}
}

func TestSmartDNSDoHBlock(t *testing.T) {
	zm := NewZoneMatcher([]string{"ru"}, nil)
	cache := NewBypassCache(10)
	sd := NewSmartDNS(zm, cache, nil, nil, nil)

	q := new(dns.Msg)
	q.SetQuestion("chrome.cloudflare-dns.com.", dns.TypeA)
	qBytes, _ := q.Pack()

	respBytes, handled, err := sd.HandleQuery(qBytes)
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}
	if !handled {
		t.Fatalf("expected DoH probe to be handled")
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBytes); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN (RcodeNameError), got %d", resp.Rcode)
	}
}
