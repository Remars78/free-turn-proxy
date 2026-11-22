package routing

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
)

type TUNRouter struct {
	inner   tun.Device
	matcher *ZoneMatcher
	cache   *BypassCache
	dns     *SmartDNS
	tcp     *TCPForwarder
	udp     *UDPForwarder
	logger  logx.Logger
}

type Config struct {
	BypassZones   []string
	BypassDomains []string
	CarrierDNS    []string
	Protect       func(fd int) bool
	Logger        logx.Logger
}

func NewTUNRouter(inner tun.Device, cfg Config) tun.Device {
	if len(cfg.BypassZones) == 0 && len(cfg.BypassDomains) == 0 {
		return inner
	}

	logger := logx.OrNop(cfg.Logger)
	matcher := NewZoneMatcher(cfg.BypassZones, cfg.BypassDomains)
	cache := NewBypassCache(0)
	dns := NewSmartDNS(matcher, cache, cfg.CarrierDNS, cfg.Protect, logger)

	r := &TUNRouter{
		inner:   inner,
		matcher: matcher,
		cache:   cache,
		dns:     dns,
		logger:  logger,
	}

	r.tcp = NewTCPForwarder(inner, cfg.Protect, logger)
	r.udp = NewUDPForwarder(inner, cfg.Protect, logger)

	logger.Infof("routing: enabled domain zone bypass for zones=%v domains=%v", matcher.Zones(), matcher.Domains())
	return r
}

func (r *TUNRouter) File() *os.File {
	return r.inner.File()
}

func (r *TUNRouter) MTU() (int, error) {
	return r.inner.MTU()
}

func (r *TUNRouter) Name() (string, error) {
	return r.inner.Name()
}

func (r *TUNRouter) Events() <-chan tun.Event {
	return r.inner.Events()
}

func (r *TUNRouter) BatchSize() int {
	return r.inner.BatchSize()
}

func (r *TUNRouter) Close() error {
	if r.tcp != nil {
		r.tcp.Close()
	}
	if r.udp != nil {
		r.udp.Close()
	}
	return r.inner.Close()
}

func (r *TUNRouter) SetCarrierDNS(servers []string) {
	if r.dns != nil {
		r.dns.SetCarrierDNS(servers)
	}
}

func (r *TUNRouter) Cache() *BypassCache {
	return r.cache
}

func (r *TUNRouter) Matcher() *ZoneMatcher {
	return r.matcher
}

func (r *TUNRouter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := r.inner.Read(bufs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}

	outIdx := 0
	for i := 0; i < n; i++ {
		pktBytes := bufs[i][offset : offset+sizes[i]]
		parsed, ok := ParsePacket(pktBytes)
		if !ok {
			if outIdx != i {
				copy(bufs[outIdx][offset:], pktBytes)
				sizes[outIdx] = sizes[i]
			}
			outIdx++
			continue
		}

		if parsed.Protocol == ProtoUDP && parsed.DstPort == 53 && len(parsed.Payload) > 0 {
			respBytes, isBypassed, dnsErr := r.dns.HandleQuery(parsed.Payload)
			if isBypassed {
				if dnsErr == nil && len(respBytes) > 0 {
					dnsRespPkt := BuildIPv4UDP(parsed.DstIP, parsed.SrcIP, parsed.DstPort, parsed.SrcPort, respBytes)
					_, _ = r.inner.Write([][]byte{dnsRespPkt}, 0)
				}
				continue
			}
		}

		if r.cache.Contains(parsed.DstIP) {
			if parsed.Protocol == ProtoTCP {
				r.tcp.HandlePacket(parsed)
				continue
			} else if parsed.Protocol == ProtoUDP {
				r.udp.HandlePacket(parsed)
				continue
			}
		}

		if outIdx != i {
			copy(bufs[outIdx][offset:], pktBytes)
			sizes[outIdx] = sizes[i]
		}
		outIdx++
	}

	return outIdx, nil
}

func (r *TUNRouter) Write(bufs [][]byte, offset int) (int, error) {
	return r.inner.Write(bufs, offset)
}
