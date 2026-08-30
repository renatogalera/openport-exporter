package config

import (
	"net/netip"
	"strconv"
	"strings"
)

type portSpan struct {
	first int
	last  int
}

// DetailTargetsWithoutScheduledOverlap returns detail allowlist entries that
// cannot be populated by any configured scheduled target. They remain valid:
// an overlapping scan submitted through the Tasks API can still populate them.
func (c *Config) DetailTargetsWithoutScheduledOverlap() []DetailTarget {
	if c == nil || c.BackgroundDetails == nil || !c.BackgroundDetails.Enabled {
		return nil
	}

	missing := make([]DetailTarget, 0)
	for _, detail := range c.BackgroundDetails.Targets {
		if !c.hasScheduledDetailOverlap(detail) {
			missing = append(missing, detail)
		}
	}
	return missing
}

func (c *Config) hasScheduledDetailOverlap(detail DetailTarget) bool {
	detailNetwork, ok := parseNetwork(detail.CIDR)
	if !ok {
		return false
	}
	detailPorts := parsePortSpans(detail.Ports)
	if len(detailPorts) == 0 {
		return false
	}
	detailProtocol := normalizeProtocol(detail.Protocol)

	for _, target := range c.Targets {
		if normalizeProtocol(target.Protocol) != detailProtocol {
			continue
		}

		targetNetwork, valid := parseNetwork(target.Target)
		if !valid || !networksOverlap(detailNetwork, targetNetwork) {
			continue
		}

		portRange := target.PortRange
		if strings.TrimSpace(portRange) == "" {
			portRange = c.Scanning.PortRange
		}
		if portSpansOverlap(detailPorts, parsePortSpans([]string{portRange})) {
			return true
		}
	}

	return false
}

func normalizeProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return "tcp"
	}
	return protocol
}

func parseNetwork(value string) (netip.Prefix, bool) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return normalizePrefix(prefix)
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), true
}

func normalizePrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	address := prefix.Addr()
	bits := prefix.Bits()
	if address.Is4In6() && bits >= 96 {
		address = address.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(address, bits).Masked(), true
}

func networksOverlap(first, second netip.Prefix) bool {
	if first.Addr().BitLen() != second.Addr().BitLen() {
		return false
	}
	return first.Contains(second.Addr()) || second.Contains(first.Addr())
}

func parsePortSpans(specifications []string) []portSpan {
	spans := make([]portSpan, 0, len(specifications))
	for _, specification := range specifications {
		for token := range strings.SplitSeq(specification, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}

			firstText, lastText, ranged := strings.Cut(token, "-")
			first, err := strconv.Atoi(strings.TrimSpace(firstText))
			if err != nil {
				continue
			}
			last := first
			if ranged {
				last, err = strconv.Atoi(strings.TrimSpace(lastText))
				if err != nil {
					continue
				}
			}
			if first < 1 || last > 65535 || first > last {
				continue
			}
			spans = append(spans, portSpan{first: first, last: last})
		}
	}
	return spans
}

func portSpansOverlap(first, second []portSpan) bool {
	for _, left := range first {
		for _, right := range second {
			if left.first <= right.last && right.first <= left.last {
				return true
			}
		}
	}
	return false
}
