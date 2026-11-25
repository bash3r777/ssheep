package master

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/frame"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
)

// AcceptOffers looks for machines that have volunteered to be a connector, and
// adds the ones this flock actually wants.
//
// This is what makes setting up one command. The master cannot know a
// connector's address in advance -- the connector is the machine with the public
// address, and the master has never spoken to it. So the connector says so
// itself, through whatever connector the flock already has, and the master takes
// it from there.
//
// Three things have to line up before an offer is believed, and the middle one is
// the point:
//
//  1. the roster lists the machine as a connector, which only the master can do;
//  2. the offer is signed by that machine, so the relay that carried it could not
//     have rewritten the address and promoted itself;
//  3. the address answers with exactly the certificate the offer claims.
func AcceptOffers(rosterPath, flockKeyPath, nodeKeyPath, connectorAddr string, out io.Writer) ([]flock.Connector, error) {
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

	have := make(map[string]bool, len(roster.Connectors))
	for _, c := range roster.Connectors {
		have[c.Addr] = true
	}

	var added []flock.Connector
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
			if have[o.Addr] || seen[o.Addr] {
				continue
			}
			seen[o.Addr] = true

			m := roster.Find(o.ID)
			if m == nil || m.Role != flock.RoleConnector {
				fmt.Fprintf(out, "  ignoring an offer from %s: not enrolled as a connector\n", nameOr(o.Name, o.ID))
				continue
			}
			if len(m.SignKey) != ed25519.PublicKeySize ||
				!ed25519.Verify(ed25519.PublicKey(m.SignKey), proto.OfferMessage(roster.ID(), o.ID, o.Addr, o.Pin), o.Sig) {
				fmt.Fprintf(out, "  ignoring an offer from %s: the signature does not verify\n", nameOr(o.Name, o.ID))
				continue
			}
			if err := probe(o.Addr, o.Pin, who); err != nil {
				fmt.Fprintf(out, "  %s offered %s, but it did not answer: %v\n", nameOr(o.Name, o.ID), o.Addr, err)
				continue
			}

			roster.UpsertConnector(flock.Connector{Addr: o.Addr, Pin: o.Pin})
			added = append(added, flock.Connector{Addr: o.Addr, Pin: o.Pin})
			fmt.Fprintf(out, "  accepted %s as a connector at %s\n", nameOr(o.Name, o.ID), o.Addr)
		}
	}
	if len(added) == 0 {
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
			if have[o.Addr] || seen[o.Addr] {
				continue
			}
			seen[o.Addr] = true
			m := roster.Find(o.ID)
			if m != nil && m.Role == flock.RoleConnector {
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
