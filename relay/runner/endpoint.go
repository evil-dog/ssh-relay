package runner

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hazaelsan/ssh-relay/relay/proto/v1/configpb"
	"github.com/hazaelsan/ssh-relay/relay/request"
	"github.com/hazaelsan/ssh-relay/response"
)

// dnsCacheEntry holds a cached DNS lookup result.
type dnsCacheEntry struct {
	addrs  []string
	expiry time.Time
}

// parsedRoute is a pre-parsed EndpointRoute for efficient matching.
type parsedRoute struct {
	relayAddress string
	hostnames    map[string]struct{}
	ips          []net.IP
	cidrs        []*net.IPNet
}

// endpointRouter resolves /endpoint ?host= queries to relay addresses.
type endpointRouter struct {
	routes      []parsedRoute
	defaultAddr string
	dnsCacheTTL time.Duration
	dnsCache    sync.Map // map[string]*dnsCacheEntry
}

// newEndpointRouter builds and validates an endpointRouter from config.
// Returns an error if any IP address or CIDR subnet in the config is invalid.
func newEndpointRouter(cfg *configpb.Config) (*endpointRouter, error) {
	er := &endpointRouter{
		defaultAddr: cfg.GetDefaultEndpointAddress(),
		dnsCacheTTL: 60 * time.Second, // default cache TTL
	}
	if er.defaultAddr == "" {
		er.defaultAddr = net.JoinHostPort(cfg.GetServerOptions().GetAddr(), cfg.GetServerOptions().GetPort())
	}
	if ttl := cfg.GetDnsCacheTtl(); ttl != nil {
		er.dnsCacheTTL = ttl.AsDuration()
	}

	for i, r := range cfg.GetEndpointRoutes() {
		pr := parsedRoute{
			relayAddress: r.GetRelayAddress(),
			hostnames:    make(map[string]struct{}),
		}
		if pr.relayAddress == "" {
			return nil, fmt.Errorf("endpoint_routes[%d]: relay_address is required", i)
		}
		for _, h := range r.GetHostnames() {
			pr.hostnames[h] = struct{}{}
		}
		for _, ipStr := range r.GetIpAddresses() {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("endpoint_routes[%d]: invalid ip_address %q", i, ipStr)
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			pr.ips = append(pr.ips, ip)
		}
		for _, cidrStr := range r.GetCidrSubnets() {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return nil, fmt.Errorf("endpoint_routes[%d]: invalid cidr_subnet %q: %w", i, cidrStr, err)
			}
			pr.cidrs = append(pr.cidrs, ipNet)
		}
		er.routes = append(er.routes, pr)
	}
	return er, nil
}

// resolve returns the relay address for the given SSH host.
// Matching priority: exact hostname → exact IP → CIDR → DNS+IP/CIDR → default.
func (er *endpointRouter) resolve(host string) string {
	if host == "" || len(er.routes) == 0 {
		return er.defaultAddr
	}

	ip := net.ParseIP(host)
	if ip != nil {
		// Host is an IP — normalize to IPv4 if possible, then match IP/CIDR.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if addr := er.matchIP(ip); addr != "" {
			return addr
		}
		return er.defaultAddr
	}

	// Host is a name — check exact hostname match first.
	for _, r := range er.routes {
		if _, ok := r.hostnames[host]; ok {
			return r.relayAddress
		}
	}

	// DNS fallback: resolve and check each resulting IP.
	for _, addrStr := range er.lookupHost(host) {
		resolved := net.ParseIP(addrStr)
		if resolved == nil {
			continue
		}
		if v4 := resolved.To4(); v4 != nil {
			resolved = v4
		}
		if addr := er.matchIP(resolved); addr != "" {
			return addr
		}
	}

	return er.defaultAddr
}

// matchIP returns the first route's relay address whose ip_addresses or
// cidr_subnets match ip. Returns "" if no route matches.
func (er *endpointRouter) matchIP(ip net.IP) string {
	for _, r := range er.routes {
		for _, rIP := range r.ips {
			if rIP.Equal(ip) {
				return r.relayAddress
			}
		}
		for _, cidr := range r.cidrs {
			if cidr.Contains(ip) {
				return r.relayAddress
			}
		}
	}
	return ""
}

// lookupHost resolves host, using the DNS cache if enabled.
func (er *endpointRouter) lookupHost(host string) []string {
	if er.dnsCacheTTL > 0 {
		if v, ok := er.dnsCache.Load(host); ok {
			e := v.(*dnsCacheEntry)
			if time.Now().Before(e.expiry) {
				return e.addrs
			}
		}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	if er.dnsCacheTTL > 0 {
		er.dnsCache.Store(host, &dnsCacheEntry{
			addrs:  addrs,
			expiry: time.Now().Add(er.dnsCacheTTL),
		})
	}
	return addrs
}

// endpointHandle handles GET /endpoint?host=SSH_HOST requests.
// Returns XSSI-protected JSON: )]}'{"endpoint":"relay.example.com:8022"}
func (r *Runner) endpointHandle(w http.ResponseWriter, req *http.Request) {
	host := req.URL.Query().Get("host")
	relayAddr := r.epRouter.resolve(host)

	// Set CORS headers so the Chrome extension can read the response.
	if origin, err := request.Origin(req, r.cfg.OriginCookieName); err == nil {
		w.Header().Add("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	b, err := response.FromEndpoint(relayAddr).MarshalXSSI()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		return
	}
}
