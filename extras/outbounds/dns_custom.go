package outbounds

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"

	"github.com/apernet/hysteria/extras/v2/outbounds/tinydoh"
)

const (
	defaultDNSTTL        = 60 * time.Second
	defaultDNSCacheSize  = 10000
)

type DNSUpstreamConfig struct {
	Type     string        `mapstructure:"type"`
	Addr     string        `mapstructure:"addr"`
	Timeout  time.Duration `mapstructure:"timeout"`
	SNI      string        `mapstructure:"sni"`
	Insecure bool          `mapstructure:"insecure"`
}

type CustomDNSRule struct {
	Suffix   string             `mapstructure:"suffix"`
	Upstream DNSUpstreamConfig  `mapstructure:"upstream"`
}

type CustomDNSConfig struct {
	Rules     []CustomDNSRule   `mapstructure:"rules"`
	DefaultUpstream DNSUpstreamConfig `mapstructure:"default"`
	CacheTTL  time.Duration     `mapstructure:"cacheTTL"`
	CacheSize int               `mapstructure:"cacheSize"`
}

type dnsCacheEntry struct {
	IPv4 net.IP
	IPv6 net.IP
	Err  error
	Exp  time.Time
}

type customDNSResolver struct {
	rules           []customDNSRule
	defaultUpstream dnsUpstream
	cache           *lru.Cache[string, dnsCacheEntry]
	cacheTTL        time.Duration
	Next            PluggableOutbound
	mu              sync.Mutex
}

type customDNSRule struct {
	suffix   string
	upstream dnsUpstream
}

type dnsUpstream interface {
	lookup4(host string) (net.IP, error)
	lookup6(host string) (net.IP, error)
}

type udpUpstream struct {
	addr   string
	client *dns.Client
}

type tcpUpstream struct {
	addr   string
	client *dns.Client
}

type tlsUpstream struct {
	addr   string
	client *dns.Client
}

type dohUpstream struct {
	resolver *tinydoh.Resolver
}

func NewCustomDNSResolver(cfg CustomDNSConfig, next PluggableOutbound) (PluggableOutbound, error) {
	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = defaultDNSTTL
	}
	cacheSize := cfg.CacheSize
	if cacheSize == 0 {
		cacheSize = defaultDNSCacheSize
	}

	cache, err := lru.New[string, dnsCacheEntry](cacheSize)
	if err != nil {
		return nil, err
	}

	rules := make([]customDNSRule, len(cfg.Rules))
	for i, rule := range cfg.Rules {
		upstream, err := newDNSUpstream(rule.Upstream)
		if err != nil {
			return nil, err
		}
		rules[i] = customDNSRule{
			suffix:   strings.ToLower(rule.Suffix),
			upstream: upstream,
		}
	}

	defaultUpstream, err := newDNSUpstream(cfg.DefaultUpstream)
	if err != nil {
		return nil, err
	}

	return &customDNSResolver{
		rules:           rules,
		defaultUpstream: defaultUpstream,
		cache:           cache,
		cacheTTL:        cacheTTL,
		Next:            next,
	}, nil
}

func newDNSUpstream(cfg DNSUpstreamConfig) (dnsUpstream, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = resolverDefaultTimeout
	}

	switch strings.ToLower(cfg.Type) {
	case "udp":
		return &udpUpstream{
			addr: addDefaultPort(cfg.Addr),
			client: &dns.Client{
				Timeout: timeout,
			},
		}, nil
	case "tcp":
		return &tcpUpstream{
			addr: addDefaultPort(cfg.Addr),
			client: &dns.Client{
				Net:     "tcp",
				Timeout: timeout,
			},
		}, nil
	case "tls", "tcp-tls":
		return &tlsUpstream{
			addr: addDefaultPortTLS(cfg.Addr),
			client: &dns.Client{
				Net:     "tcp-tls",
				Timeout: timeout,
				TLSConfig: &tls.Config{
					ServerName:         cfg.SNI,
					InsecureSkipVerify: cfg.Insecure,
				},
			},
		}, nil
	case "https", "http", "doh":
		addr := cfg.Addr
		if !strings.HasPrefix(addr, "https://") {
			addr = "https://" + addr + "/dns-query"
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         cfg.SNI,
				InsecureSkipVerify: cfg.Insecure,
			},
		}
		return &dohUpstream{
			resolver: &tinydoh.Resolver{
				URL: addr,
				HTTPClient: &http.Client{
					Transport: tr,
					Timeout:   timeout,
				},
			},
		}, nil
	default:
		return nil, errors.New("unsupported DNS upstream type")
	}
}

func (u *udpUpstream) lookup4(host string) (net.IP, error) {
	return lookup4WithClient(u.client, u.addr, host)
}

func (u *udpUpstream) lookup6(host string) (net.IP, error) {
	return lookup6WithClient(u.client, u.addr, host)
}

func (u *tcpUpstream) lookup4(host string) (net.IP, error) {
	return lookup4WithClient(u.client, u.addr, host)
}

func (u *tcpUpstream) lookup6(host string) (net.IP, error) {
	return lookup6WithClient(u.client, u.addr, host)
}

func (u *tlsUpstream) lookup4(host string) (net.IP, error) {
	return lookup4WithClient(u.client, u.addr, host)
}

func (u *tlsUpstream) lookup6(host string) (net.IP, error) {
	return lookup6WithClient(u.client, u.addr, host)
}

func lookup4WithClient(client *dns.Client, addr, host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	resp, _, err := client.Exchange(m, addr)
	if err != nil {
		return nil, err
	}
	for _, a := range resp.Answer {
		if aa, ok := a.(*dns.A); ok {
			return aa.A.To4(), nil
		}
	}
	return nil, nil
}

func lookup6WithClient(client *dns.Client, addr, host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	m.RecursionDesired = true
	resp, _, err := client.Exchange(m, addr)
	if err != nil {
		return nil, err
	}
	for _, a := range resp.Answer {
		if aa, ok := a.(*dns.AAAA); ok {
			return aa.AAAA.To16(), nil
		}
	}
	return nil, nil
}

func (u *dohUpstream) lookup4(host string) (net.IP, error) {
	ips, err := u.resolver.LookupA(host)
	if err != nil {
		return nil, err
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return nil, nil
}

func (u *dohUpstream) lookup6(host string) (net.IP, error) {
	ips, err := u.resolver.LookupAAAA(host)
	if err != nil {
		return nil, err
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return nil, nil
}

func (r *customDNSResolver) selectUpstream(host string) dnsUpstream {
	hostLower := strings.ToLower(host)
	for _, rule := range r.rules {
		if strings.HasSuffix(hostLower, rule.suffix) {
			return rule.upstream
		}
	}
	return r.defaultUpstream
}

func (r *customDNSResolver) getCached(host string) (dnsCacheEntry, bool) {
	entry, ok := r.cache.Get(host)
	if !ok {
		return dnsCacheEntry{}, false
	}
	if time.Now().After(entry.Exp) {
		r.cache.Remove(host)
		return dnsCacheEntry{}, false
	}
	return entry, true
}

func (r *customDNSResolver) setCached(host string, entry dnsCacheEntry) {
	entry.Exp = time.Now().Add(r.cacheTTL)
	r.cache.Add(host, entry)
}

func (r *customDNSResolver) resolve(reqAddr *AddrEx) {
	if tryParseIP(reqAddr) {
		return
	}

	host := reqAddr.Host

	if entry, ok := r.getCached(host); ok {
		reqAddr.ResolveInfo = &ResolveInfo{
			IPv4: entry.IPv4,
			IPv6: entry.IPv6,
			Err:  entry.Err,
		}
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.getCached(host); ok {
		reqAddr.ResolveInfo = &ResolveInfo{
			IPv4: entry.IPv4,
			IPv6: entry.IPv6,
			Err:  entry.Err,
		}
		return
	}

	upstream := r.selectUpstream(host)

	type lookupResult struct {
		ip  net.IP
		err error
	}
	ch4, ch6 := make(chan lookupResult, 1), make(chan lookupResult, 1)

	go func() {
		var ip net.IP
		var err error
		for i := 0; i < standardResolverRetryTimes; i++ {
			ip, err = upstream.lookup4(host)
			if err == nil {
				break
			}
		}
		ch4 <- lookupResult{ip, err}
	}()

	go func() {
		var ip net.IP
		var err error
		for i := 0; i < standardResolverRetryTimes; i++ {
			ip, err = upstream.lookup6(host)
			if err == nil {
				break
			}
		}
		ch6 <- lookupResult{ip, err}
	}()

	result4, result6 := <-ch4, <-ch6

	var resolveErr error
	if result4.err != nil {
		resolveErr = result4.err
	} else if result6.err != nil {
		resolveErr = result6.err
	}

	entry := dnsCacheEntry{
		IPv4: result4.ip,
		IPv6: result6.ip,
		Err:  resolveErr,
	}
	r.setCached(host, entry)

	reqAddr.ResolveInfo = &ResolveInfo{
		IPv4: result4.ip,
		IPv6: result6.ip,
		Err:  resolveErr,
	}
}

func (r *customDNSResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

func (r *customDNSResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}

func (r *customDNSResolver) CheckUDP(reqAddr *AddrEx) error {
	r.resolve(reqAddr)
	return r.Next.CheckUDP(reqAddr)
}
