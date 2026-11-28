package master

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/frame"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
)

// AcceptOffers looks for machines that have volunteered to be a relay, and adds
// the ones this flock actually wants.
//
// This is what makes setting up one command. The master cannot know a machine's
// address in advance -- the machine with the public address is the one that has
// never been spoken to. So it says so itself, through a relay the flock already
// has, and the master takes it from there.
//
// Three things have to line up before an offer is believed, and the middle one is
// the point:
//
//  1. the roster says the machine may relay, which only the master can grant;
//  2. the offer is signed by that machine, so the relay that carried it could not
//     have rewritten the address and promoted itself;
//  3. the address answers with exactly the certificate the offer claims.
//
// A machine may offer several addresses at once -- a global IPv6 address, a
// forwarded port, its address on the local network -- because only the master can
// tell which of them the flock can actually reach. The first that answers wins,
// and the flock keeps one relay per machine: more would only mean more links on
// every machine for no extra reach.
//
// max caps how many relays a flock keeps. Zero means no limit.
func AcceptOffers(rosterPath, flockKeyPath, nodeKeyPath, connectorAddr string, max int, out io.Writer) ([]flock.Connector, error) {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return nil, err
	}
	roster, err := sr.Verify()
	if err != nil {
		return nil, err
	}
	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return nil, err
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return nil, err
	}
	who := peer.Identity{
		Flock:  roster.ID(),
		NodeID: flock.NodeID(key.SignPub()),
		Key:    key.SignKey(),
		Roster: sr,
	}

	connectors, err := roster.ConnectorsFor(connectorAddr)
	if err != nil {
		// Nowhere to hear an offer from. Not an error: the flock may be brand new.
		return nil, nil
	}

	// Ask every relay what it is holding, and group what comes back by the
	// machine that offered it.
	byMachine := map[string][]proto.Offer{}
	var order []string
	seen := map[string]bool{}
	for _, cn := range connectors {
		conn, err := peer.Dial(cn.Addr, cn.Pin, who, dialTimeout)
		if err != nil {
			continue
		}
		reply, err := listOn(conn)
		conn.Close()
		if err != nil {
			continue
		}
		for _, o := range reply.Offers {
			k := o.ID + "|" + o.Addr
			if seen[k] {
				continue
			}
			seen[k] = true
			if _, ok := byMachine[o.ID]; !ok {
				order = append(order, o.ID)
			}
			byMachine[o.ID] = append(byMachine[o.ID], o)
		}
	}
	if len(order) == 0 {
		return nil, nil
	}

	// A machine that moved leaves its old address behind. Drop the automatic
	// relays that have stopped answering first, so the flock keeps making room
	// for the machines that are actually there.
	pruned, alive := pruneRelays(&roster, who, out)
	changed := pruned > 0

	relaying := map[string]string{}
	for _, c := range roster.Connectors {
		if c.By != "" {
			relaying[c.By] = c.Addr
		}
	}
	have := map[string]bool{}
	for _, c := range roster.Connectors {
		have[c.Addr] = true
	}

	// Decide what is worth a dial: a signed offer from a machine that may relay,
	// at an address the flock does not already use.
	var probeAddrs []string
	byAddr := map[string]proto.Offer{}
	for _, id := range order {
		os := byMachine[id]
		// The order the machine sent them is the order it prefers: IPv6 first,
		// then what a relay sees it as, then its addresses on the local network.
		sort.Slice(os, func(i, j int) bool { return os[i].At.Before(os[j].At) })

		m := roster.Find(id)
		if m == nil || !m.MayRelay() {
			fmt.Fprintf(out, "  ignoring an offer from %s: not a machine that may relay\n", nameOr(os[0].Name, id))
			continue
		}
		if addr, ok := relaying[id]; ok && alive[addr] {
			// Already relaying, and its relay answers. Nothing to do.
			continue
		}
		for _, o := range os {
			if have[o.Addr] {
				continue
			}
			if len(m.SignKey) != ed25519.PublicKeySize ||
				!ed25519.Verify(ed25519.PublicKey(m.SignKey), proto.OfferMessage(roster.ID(), o.ID, o.Addr, o.Pin), o.Sig) {
				fmt.Fprintf(out, "  ignoring an offer from %s: the signature does not verify\n", nameOr(o.Name, o.ID))
				continue
			}
			if _, dup := byAddr[o.Addr]; dup {
				continue
			}
			byAddr[o.Addr] = o
			probeAddrs = append(probeAddrs, o.Addr)
		}
	}

	// Dial them all at once. A machine behind a NAT offers several addresses and
	// none of them answer; one timeout per address would make the master wait
	// minutes for a flock of them.
	up := probeMany(probeAddrs, byAddr, who)

	// Take one relay per machine, in the order the machine offered its addresses.
	var added []flock.Connector
	took := map[string]bool{}
	for _, id := range order {
		if took[id] {
			continue
		}
		os := byMachine[id]
		sort.Slice(os, func(i, j int) bool { return os[i].At.Before(os[j].At) })

		m := roster.Find(id)
		if m == nil || !m.MayRelay() {
			continue
		}
		if addr, ok := relaying[id]; ok && alive[addr] {
			continue
		}
		if max > 0 && len(roster.Connectors) >= max {
			fmt.Fprintf(out, "  %d relays is plenty for now\n", len(roster.Connectors))
			break
		}

		var tried []string
		for _, o := range os {
			if have[o.Addr] {
				continue
			}
			if _, ok := byAddr[o.Addr]; !ok {
				continue // did not pass the signature check above
			}
			if !up[o.Addr] {
				tried = append(tried, o.Addr)
				continue
			}
			c := flock.Connector{Addr: o.Addr, Pin: o.Pin, By: o.ID}
			roster.UpsertConnector(c)
			added = append(added, c)
			have[o.Addr] = true
			took[id] = true
			changed = true
			fmt.Fprintf(out, "  accepted %s as a relay at %s\n", nameOr(o.Name, o.ID), o.Addr)
			break // one relay per machine
		}
		if !took[id] && len(tried) > 0 {
			// One line per machine, not per address: a machine behind a NAT
			// offers several addresses and none of them work, and saying so
			// four times is noise.
			fmt.Fprintf(out, "  %s offered to relay at %s, but nothing answered\n", nameOr(os[0].Name, id), strings.Join(tried, ", "))
		}
	}
	if !changed {
		return nil, nil
	}

	roster = roster.Bump()
	signed, err := flock.SignRoster(roster, authority.SignKey())
	if err != nil {
		return nil, err
	}
	if err := signed.Save(rosterPath); err != nil {
		return nil, err
	}
	if _, err := Publish(rosterPath, nodeKeyPath); err != nil {
		fmt.Fprintf(out, "  the roster could not be published: %v\n", err)
	}
	return added, nil
}

// probeMany dials every offered address at once, with a bound, and reports which
// ones answered.
func probeMany(addrs []string, byAddr map[string]proto.Offer, who peer.Identity) map[string]bool {
	up := make(map[string]bool, len(addrs))
	if len(addrs) == 0 {
		return up
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for _, a := range addrs {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok := probe(a, byAddr[a].Pin, who) == nil
			mu.Lock()
			up[a] = ok
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	return up
}

// pruneRelays drops the automatic relays that have stopped answering, so a
// machine that has moved or gone away does not hold a slot forever.
//
// Only relays a machine offered are dropped on their own: one the operator added
// by hand -- the project's relay, or `connector add` -- is the operator's to
// remove. And it does nothing at all when no relay answers, because that means
// this machine's network is down rather than that every relay died, and dropping
// them all would leave the flock with no way in.
func pruneRelays(r *flock.Roster, who peer.Identity, out io.Writer) (int, map[string]bool) {
	alive := map[string]bool{}
	if len(r.Connectors) == 0 {
		return 0, alive
	}
	type res struct {
		addr string
		ok   bool
	}
	ch := make(chan res, len(r.Connectors))
	for _, c := range r.Connectors {
		go func(c flock.Connector) { ch <- res{c.Addr, probe(c.Addr, c.Pin, who) == nil} }(c)
	}
	any := false
	for range r.Connectors {
		x := <-ch
		alive[x.addr] = x.ok
		if x.ok {
			any = true
		}
	}
	if !any {
		return 0, alive
	}

	kept := r.Connectors[:0]
	removed := 0
	for _, c := range r.Connectors {
		if c.By != "" && !alive[c.Addr] {
			removed++
			fmt.Fprintf(out, "  dropped %s: the machine that offered it is not answering there\n", c.Addr)
			continue
		}
		kept = append(kept, c)
	}
	r.Connectors = kept
	return removed, alive
}

// PendingOffers reports offers waiting to be accepted, without touching anything.
func PendingOffers(rosterPath, nodeKeyPath, connectorAddr string) ([]proto.Offer, error) {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return nil, err
	}
	roster, err := sr.Verify()
	if err != nil {
		return nil, err
	}
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return nil, err
	}
	connectors, err := roster.ConnectorsFor(connectorAddr)
	if err != nil {
		return nil, nil
	}
	have := map[string]bool{}
	for _, c := range roster.Connectors {
		have[c.Addr] = true
	}
	relaying := map[string]bool{}
	for _, c := range roster.Connectors {
		if c.By != "" {
			relaying[c.By] = true
		}
	}
	who := peer.Identity{Flock: roster.ID(), NodeID: flock.NodeID(key.SignPub()), Key: key.SignKey(), Roster: sr}

	var out []proto.Offer
	seen := map[string]bool{}
	for _, cn := range connectors {
		conn, err := peer.Dial(cn.Addr, cn.Pin, who, dialTimeout)
		if err != nil {
			continue
		}
		reply, err := listOn(conn)
		conn.Close()
		if err != nil {
			continue
		}
		for _, o := range reply.Offers {
			k := o.ID + "|" + o.Addr
			if have[o.Addr] || seen[k] {
				continue
			}
			seen[k] = true
			m := roster.Find(o.ID)
			if m != nil && m.MayRelay() && !relaying[o.ID] {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

func listOn(c *frame.Conn) (proto.ListReply, error) {
	var empty proto.ListReply
	if err := peer.Send(c, proto.Wrap(proto.TypeList, nil)); err != nil {
		return empty, err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := peer.Read(c)
	if err != nil {
		return empty, err
	}
	if env.Type != proto.TypeListReply {
		return empty, errors.New("master: the connector did not answer with a list")
	}
	var r proto.ListReply
	if err := env.Decode(&r); err != nil {
		return empty, err
	}
	return r, nil
}

func probe(addr, pin string, who peer.Identity) error {
	conn, err := peer.Dial(addr, pin, who, dialTimeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func nameOr(name, id string) string {
	if name != "" {
		return name
	}
	return id
}
