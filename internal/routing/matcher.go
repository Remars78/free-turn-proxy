package routing

import (
	"strings"

	"golang.org/x/net/idna"
)

// ZoneMatcher проверяет соответствие доменного имени исключаемым зонам и доменам.
type ZoneMatcher struct {
	zones   []string
	domains []string
}

// NewZoneMatcher создает новый сопоставитель доменов и зон.
// Зоны и домены автоматически приводятся к нижнему регистру и нормализуются через Punycode/IDNA (например, "рф" -> "xn--p1ai").
func NewZoneMatcher(zones []string, domains []string) *ZoneMatcher {
	zm := &ZoneMatcher{
		zones:   make([]string, 0, len(zones)),
		domains: make([]string, 0, len(domains)),
	}

	for _, z := range zones {
		norm := normalizeZone(z)
		if norm != "" {
			zm.zones = append(zm.zones, norm)
		}
	}
	for _, d := range domains {
		norm := normalizeDomain(d)
		if norm != "" {
			zm.domains = append(zm.domains, norm)
		}
	}
	return zm
}

// IsBypassed возвращает true, если переданный домен оканчивается на одну из заданных зон
// или совпадает с одним из заданных доменов.
func (m *ZoneMatcher) IsBypassed(domain string) bool {
	if m == nil || (len(m.zones) == 0 && len(m.domains) == 0) {
		return false
	}
	norm := normalizeDomain(domain)
	if norm == "" {
		return false
	}

	for _, d := range m.domains {
		if norm == d || strings.HasSuffix(norm, "."+d) {
			return true
		}
	}

	for _, z := range m.zones {
		if norm == z || strings.HasSuffix(norm, "."+z) {
			return true
		}
	}

	return false
}

// Zones возвращает нормализованный список зон.
func (m *ZoneMatcher) Zones() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.zones...)
}

// Domains возвращает нормализованный список доменов.
func (m *ZoneMatcher) Domains() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.domains...)
}

func normalizeZone(zone string) string {
	zone = strings.TrimSpace(strings.ToLower(zone))
	zone = strings.TrimPrefix(zone, ".")
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return ""
	}
	ascii, err := idna.ToASCII(zone)
	if err == nil && ascii != "" {
		return ascii
	}
	return zone
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return ""
	}
	ascii, err := idna.ToASCII(domain)
	if err == nil && ascii != "" {
		return ascii
	}
	return domain
}
