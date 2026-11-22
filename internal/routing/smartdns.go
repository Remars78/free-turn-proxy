package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
)

var defaultCarrierDNS = []string{
	"77.88.8.8:53",
	"77.88.8.1:53",
}

const (
	dnsTimeout = 3 * time.Second
)

// SmartDNS отвечает за умный резолвинг DNS-запросов:
// запросы к исключаемым зонам резолвятся через системный/провайдерский DNS с сохранением IP в кэш обхода.
type SmartDNS struct {
	matcher    *ZoneMatcher
	cache      *BypassCache
	carrierDNS []string
	protect    func(fd int) bool
	logger     logx.Logger
	mu         sync.RWMutex
}

// NewSmartDNS создает новый резолвер SmartDNS.
func NewSmartDNS(matcher *ZoneMatcher, cache *BypassCache, carrierDNS []string, protect func(fd int) bool, logger logx.Logger) *SmartDNS {
	sd := &SmartDNS{
		matcher: matcher,
		cache:   cache,
		protect: protect,
		logger:  logx.OrNop(logger),
	}
	sd.SetCarrierDNS(carrierDNS)
	return sd
}

// SetCarrierDNS обновляет список провайдерских DNS-серверов.
func (s *SmartDNS) SetCarrierDNS(servers []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var normalized []string
	for _, srv := range servers {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !strings.Contains(srv, ":") {
			srv = net.JoinHostPort(srv, "53")
		}
		normalized = append(normalized, srv)
	}
	if len(normalized) == 0 {
		normalized = defaultCarrierDNS
	}
	s.carrierDNS = normalized
	s.logger.Infof("smartdns: configured carrier DNS servers: %v", s.carrierDNS)
}

func makeControl(protect func(fd int) bool) func(network, address string, c syscall.RawConn) error {
	if protect == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var protectErr error
		err := c.Control(func(fd uintptr) {
			if !protect(int(fd)) {
				protectErr = fmt.Errorf("protect socket %d failed", fd)
			}
		})
		if err != nil {
			return err
		}
		return protectErr
	}
}

func isDoHDomain(name string) bool {
	lower := strings.ToLower(name)
	if lower == "use-application-dns.net" {
		return true
	}
	if strings.HasSuffix(lower, ".cloudflare-dns.com") || lower == "cloudflare-dns.com" {
		return true
	}
	if lower == "dns.google" || lower == "dns.quad9.net" || lower == "doh.opendns.com" || lower == "dns.adguard-dns.com" {
		return true
	}
	return false
}

// HandleQuery анализирует raw DNS-пакет. Если запрашиваемый домен в зоне обхода,
// запрос отправляется в carrier DNS, из ответа извлекаются IP и сохраняются в кэш.
// Возвращает ответ и флаг true, если запрос был перехвачен и обработан SmartDNS.
func (s *SmartDNS) HandleQuery(rawQuery []byte) ([]byte, bool, error) {
	if s == nil || s.matcher == nil {
		return nil, false, nil
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(rawQuery); err != nil {
		return nil, false, err
	}
	if len(msg.Question) == 0 {
		return nil, false, nil
	}

	q := msg.Question[0]
	qname := strings.TrimSuffix(q.Name, ".")

	// Блокировка DoH провайдеров и canary domain для принудительного отката браузеров (Chrome, Firefox) на системный DNS (UDP:53).
	if isDoHDomain(qname) {
		s.logger.Infof("smartdns: blocked DoH probe for %s -> returning NXDOMAIN to force system DNS fallback", qname)
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeNameError) // NXDOMAIN
		resp.RecursionAvailable = true
		respBytes, err := resp.Pack()
		return respBytes, true, err
	}

	bypassed := s.matcher.IsBypassed(qname)
	s.logger.Infof("smartdns: query %s (id %d, type %d) -> bypass=%v", qname, msg.Id, q.Qtype, bypassed)

	if !bypassed {
		return nil, false, nil
	}

	// Для исключаемых зон: если это запрос IPv6 (AAAA), возвращаем пустой ответ NOERROR (без записей).
	// В мобильных сетях прямой IPv6 часто недоступен, и это предотвращает задержки и таймауты подключения.
	if q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.RecursionAvailable = true
		respBytes, err := resp.Pack()
		return respBytes, true, err
	}

	respBytes, err := s.queryUpstream(rawQuery, msg.Id)
	if err != nil {
		s.logger.Warnf("smartdns: direct resolution of %s failed: %v", qname, err)
		return nil, true, err
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBytes); err == nil {
		for _, rr := range respMsg.Answer {
			var ip netip.Addr
			var ttl uint32
			switch v := rr.(type) {
			case *dns.A:
				if v4, ok := netip.AddrFromSlice(v.A); ok {
					ip = v4
					ttl = v.Hdr.Ttl
				}
			case *dns.AAAA:
				if v6, ok := netip.AddrFromSlice(v.AAAA); ok {
					ip = v6
					ttl = v.Hdr.Ttl
				}
			}
			if ip.IsValid() {
				s.cache.Add(ip, time.Duration(ttl)*time.Second)
				s.logger.Infof("smartdns: cached direct IP %s for %s (ttl %ds)", ip, qname, ttl)
			}
		}
	}

	return respBytes, true, nil
}

func (s *SmartDNS) queryUpstream(query []byte, origID uint16) ([]byte, error) {
	s.mu.RLock()
	servers := append([]string(nil), s.carrierDNS...)
	s.mu.RUnlock()

	var lastErr error
	for _, server := range servers {
		resp, err := s.queryOne(server, query, origID)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}

	// Fallback на дефолтные DNS, если провайдерские не ответили
	for _, server := range defaultCarrierDNS {
		resp, err := s.queryOne(server, query, origID)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no upstream carrier DNS available")
}

func (s *SmartDNS) queryOne(server string, query []byte, origID uint16) ([]byte, error) {
	dialer := &net.Dialer{
		Timeout: dnsTimeout,
		Control: makeControl(s.protect),
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", server, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(dnsTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write to upstream: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from upstream: %w", err)
	}

	resp := buf[:n]
	if len(resp) >= 2 {
		resp[0] = byte(origID >> 8)
		resp[1] = byte(origID)
	}

	return resp, nil
}
