package allowlist

import (
	"net"
	"strconv"
	"strings"
)

// Entry represents a single allowlist rule used to build the cache.
type Entry struct {
	Alias    string
	CIDR     string // CIDR or single IP
	Protocol string // tcp/udp
	Ports    []string
}

// PortOwner links a port to a potential owner (CIDR/IP + Alias).
type PortOwner struct {
	Alias   string
	Network *net.IPNet
	IP      net.IP
}

// Cache: map[protocol][port] -> list of owners (CIDR/IP + Alias)
type Cache struct {
	protocolPortMap map[string]map[int][]*PortOwner
}

// Build constructs the cache from the entries.
func Build(entries []Entry) *Cache {
	c := &Cache{protocolPortMap: make(map[string]map[int][]*PortOwner)}
	for _, e := range entries {
		proto := strings.ToLower(strings.TrimSpace(e.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		if c.protocolPortMap[proto] == nil {
			c.protocolPortMap[proto] = make(map[int][]*PortOwner)
		}

		// Parse CIDR/IP
		var owner PortOwner
		owner.Alias = e.Alias
		if ip := net.ParseIP(strings.TrimSpace(e.CIDR)); ip != nil {
			owner.IP = ip
		} else if _, nw, err := net.ParseCIDR(strings.TrimSpace(e.CIDR)); err == nil && nw != nil {
			owner.Network = nw
		} else {
			// invalid; skip
			continue
		}

		// Single pointer per entry to avoid per-port copies
		ownerPtr := &owner

		// For each port, append the owner pointer to the list
		for _, ps := range e.Ports {
			ps = strings.TrimSpace(ps)
			if ps == "" {
				continue
			}
			if strings.Contains(ps, "-") {
				parts := strings.SplitN(ps, "-", 2)
				if len(parts) != 2 {
					continue
				}
				a, errA := strconv.Atoi(parts[0])
				b, errB := strconv.Atoi(parts[1])
				if errA != nil || errB != nil || a < 1 || b < 1 || a > 65535 || b > 65535 || a > b {
					continue
				}
				for p := a; p <= b; p++ {
					c.protocolPortMap[proto][p] = append(c.protocolPortMap[proto][p], ownerPtr)
				}
			} else {
				p, err := strconv.Atoi(ps)
				if err != nil || p < 1 || p > 65535 {
					continue
				}
				c.protocolPortMap[proto][p] = append(c.protocolPortMap[proto][p], ownerPtr)
			}
		}
	}
	return c
}

// Lookup returns the alias if ip/port/protocol is allowlisted.
func (c *Cache) Lookup(ip, port, proto string) (string, bool) {
	if c == nil {
		return "", false
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return "", false
	}
	proto = strings.ToLower(proto)
	portsByProto, ok := c.protocolPortMap[proto]
	if !ok {
		return "", false
	}
	owners, ok := portsByProto[pn]
	if !ok || len(owners) == 0 {
		return "", false
	}
	hip := net.ParseIP(ip)
	if hip == nil {
		return "", false
	}
	for _, ow := range owners {
		if (ow.IP != nil && ow.IP.Equal(hip)) || (ow.Network != nil && ow.Network.Contains(hip)) {
			return ow.Alias, true
		}
	}
	return "", false
}
