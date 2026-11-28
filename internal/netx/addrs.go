package netx

import (
	"net"
	"strconv"
)

// MaxCandidates keeps an offer list to the plausible few. Every candidate costs
// the master a dial, and a machine with container bridges has plenty of addresses
// nobody could ever reach.
const MaxCandidates = 4

// CandidateAddrs is every address a machine might be reachable at, best guess
// first.
//
// All of them are offered and the master keeps the ones that answer, which is
// what lets a machine relay without anybody having to decide whether it can:
//
//   - a global IPv6 address, because a machine with one needs no NAT at all;
//   - what a relay sees it as, which is right when a port is forwarded;
//   - its own addresses on the local network, which is right when the master is
//     on the same network -- a homelab is the normal case, and there the public
//     address is the one thing that will not work.
//
// youAre may be empty, for a machine that has not been told what it looks like.
func CandidateAddrs(youAre string, port int) []string {
	p := strconv.Itoa(port)
	var out []string
	if v6 := GlobalIPv6(); v6 != "" {
		out = append(out, net.JoinHostPort(v6, p))
	}
	if host, _, err := net.SplitHostPort(youAre); err == nil && host != "" {
		out = append(out, net.JoinHostPort(host, p))
	}
	for _, v4 := range LocalIPv4s() {
		out = append(out, net.JoinHostPort(v4, p))
	}
	out = Dedupe(out)
	if len(out) > MaxCandidates {
		out = out[:MaxCandidates]
	}
	return out
}

// GlobalIPv6 finds an address the rest of the internet could dial: global
// unicast, not loopback, not link-local, and not a private ULA.
func GlobalIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipnet.IP.To4() != nil || !ipnet.IP.IsGlobalUnicast() {
			continue
		}
		// fc00::/7 is the private range for IPv6, the equivalent of 10.0.0.0/8.
		if len(ipnet.IP) == net.IPv6len && (ipnet.IP[0]&0xfe) == 0xfc {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}

// LocalIPv4s are the IPv4 addresses this machine has on networks it might be
// reached on.
func LocalIPv4s() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipnet.IP.To4() == nil {
			continue
		}
		out = append(out, ipnet.IP.String())
	}
	return out
}

// Dedupe removes empty and repeated addresses, keeping the order.
func Dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
