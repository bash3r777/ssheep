package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/invite"
	"ssheep.xyz/internal/master"
	"ssheep.xyz/internal/netx"
)

// cmdMaster is the whole setup in one command: create the flock, hand out
// tickets, and print the two lines somebody has to paste somewhere else.
//
// Everything here has a default, and the defaults are meant to work without
// being read. The flags exist for when they do not.
func cmdMaster(args []string) error {
	fs := newFlagSet("master")
	name := fs.String("name", "", "flock name (default: this machine's hostname)")
	relay := fs.String("relay", defaultRelay, `public relay to start with ("" for none)`)
	private := fs.Bool("private", false, "use only connectors you run yourself")
	sheepN := fs.Int("sheep", defaultSheep, "how many sheep tickets to mint")
	connN := fs.Int("connector", 1, "how many connector tickets to mint")
	inviteMore := fs.Bool("invite", false, "mint fresh tickets even though the flock exists")
	watch := fs.Duration("watch", 0, "keep watching for machines joining, e.g. --watch 3m")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *private {
		*relay = ""
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)

	fresh := false
	if _, err := os.Stat(rosterPath); err != nil {
		if err := newFlock(rosterPath, flockKeyPath, nodeKeyPath, *name, *relay); err != nil {
			return err
		}
		fresh = true
	}

	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	roster, err := sr.Verify()
	if err != nil {
		return err
	}

	fmt.Printf("👑  master ready — flock %q\n\n", roster.Name)
	fmt.Printf("    roster      %s\n", rosterPath)
	fmt.Printf("    authority   %s\n", flockKeyPath)
	fmt.Printf("                keep this offline; it is never needed on a connector\n")
	if len(roster.Connectors) == 0 {
		fmt.Printf("    connectors  none yet — start one and it will register itself\n")
	} else {
		for i, c := range roster.Connectors {
			label := "connectors "
			if i > 0 {
				label = "           "
			}
			fmt.Printf("    %s %s\n", label, c.Addr)
		}
	}

	if fresh || *inviteMore {
		if err := printTickets(rosterPath, flockKeyPath, *sheepN, *connN); err != nil {
			return err
		}
	}

	// A connector that was started since the last run is waiting to be believed.
	fmt.Println()
	if pending, _ := master.PendingOffers(rosterPath, nodeKeyPath, ""); len(pending) > 0 {
		fmt.Printf("connectors waiting to register:\n")
		if _, err := master.AcceptOffers(rosterPath, flockKeyPath, nodeKeyPath, "", os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "ssheep: %v\n", err)
		}
	}

	report(rosterPath, nodeKeyPath, *dir)

	if *watch > 0 {
		return watchFlock(rosterPath, flockKeyPath, nodeKeyPath, *dir, *watch)
	}
	return nil
}

// newFlock creates the flock key, this machine's key, and a roster with a public
// relay already in it, so the flock works before its owner has done anything
// else.
func newFlock(rosterPath, flockKeyPath, nodeKeyPath, name, relay string) error {
	authority, err := flock.NewKeyFile()
	if err != nil {
		return err
	}
	thisMachine, err := flock.NewKeyFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(flock.Dir(), 0o700); err != nil {
		return err
	}
	if err := authority.Save(flockKeyPath); err != nil {
		return err
	}
	if err := thisMachine.Save(nodeKeyPath); err != nil {
		return err
	}

	host, _ := os.Hostname()
	if name == "" {
		name = host
	}
	kex, err := thisMachine.KexPub()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := flock.Roster{
		Version:  1,
		Name:     name,
		FlockKey: authority.SignPub(),
		Members: []flock.Member{{
			ID:      flock.NodeID(thisMachine.SignPub()),
			Name:    host,
			Role:    flock.RoleMaster,
			SignKey: thisMachine.SignPub(),
			KexKey:  kex,
			Added:   now,
		}},
		IssuedAt: now,
	}

	if relay != "" {
		pin, err := netx.FetchPin(relay, 10*time.Second)
		switch {
		case err == nil:
			r.Connectors = []flock.Connector{{Addr: relay, Pin: pin}}
		default:
			fmt.Fprintf(os.Stderr, "ssheep: %s did not answer, so the flock starts with no connector.\n", relay)
			fmt.Fprintf(os.Stderr, "        Start one with `ssheep connector \"<ticket>\"` and it will register itself.\n\n")
		}
	}

	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	return sr.Save(rosterPath)
}

// printTickets mints the tickets and prints the two lines to paste elsewhere.
func printTickets(rosterPath, flockKeyPath string, sheepN, connN int) error {
	fmt.Printf("\nRun this on each machine you want in the flock — one ticket each:\n\n")
	for i := 1; i <= sheepN; i++ {
		blob, err := mintInvite(rosterPath, flockKeyPath, fmt.Sprintf("sheep-%d", i), flock.RoleSheep)
		if err != nil {
			return err
		}
		fmt.Printf("    ssheep sheep %q\n", blob)
	}
	fmt.Printf("\nRun this on the machine that will be its connector — the one with a public\naddress, usually a small VPS:\n\n")
	for i := 1; i <= connN; i++ {
		name := "connector-1"
		if connN > 1 {
			name = fmt.Sprintf("connector-%d", i)
		}
		blob, err := mintInvite(rosterPath, flockKeyPath, name, flock.RoleConnector)
		if err != nil {
			return err
		}
		fmt.Printf("    ssheep connector %q\n", blob)
	}
	fmt.Printf("\nEach ticket works once, and carries a private key: hand it over privately.\n")
	if sheepN > 0 {
		fmt.Printf("Tickets you do not use can be dropped again with `ssheep forget --name sheep-%d`.\n", sheepN)
	}
	fmt.Printf("More anytime with `ssheep master --invite`.\n")
	return nil
}

// mintInvite adds a member and returns a ticket for it.
func mintInvite(rosterPath, flockKeyPath, name, role string) (string, error) {
	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return "", err
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return "", err
	}
	r, err := sr.Verify()
	if err != nil {
		return "", err
	}
	machine, err := flock.NewKeyFile()
	if err != nil {
		return "", err
	}
	kex, err := machine.KexPub()
	if err != nil {
		return "", err
	}
	id := flock.NodeID(machine.SignPub())
	r.Upsert(flock.Member{
		ID:      id,
		Name:    name,
		Role:    role,
		SignKey: machine.SignPub(),
		KexKey:  kex,
		Added:   time.Now().UTC().Truncate(time.Second),
	})
	r = r.Bump()
	sr, err = flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return "", err
	}
	if err := sr.Save(rosterPath); err != nil {
		return "", err
	}
	return invite.Encode(&invite.Invite{
		Version:  invite.Version,
		Roster:   *sr,
		NodeID:   id,
		Name:     name,
		Role:     role,
		SignSeed: machine.SignSeed,
		KexSeed:  machine.KexSeed,
	})
}

// argValue finds a flag's value in raw arguments. It exists for the few places
// that need to know where the state lives before any flag set has parsed it.
func argValue(args []string, name string) string {
	for i, a := range args {
		if a == "--"+name && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v
		}
	}
	return ""
}

// enrolledRole reports what this machine is enrolled as, or "" if it is not
// enrolled at all.
func enrolledRole(dir string) string {
	rosterPath, _, nodeKeyPath := state(dir)
	key, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return ""
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return ""
	}
	r, err := sr.Verify()
	if err != nil {
		return ""
	}
	if m := r.Find(flock.NodeID(key.SignPub())); m != nil {
		return m.Role
	}
	return ""
}

// report prints where the flock stands, without failing if it cannot be reached.
func report(rosterPath, nodeKeyPath, dir string) {
	cl, err := open(dir, "")
	if err != nil {
		fmt.Printf("\nnot reachable from here right now: %v\n", err)
		fmt.Printf("start a connector, then run `ssheep see`.\n")
		return
	}
	defer cl.Close()
	reply, err := cl.List(10 * time.Second)
	if err != nil {
		fmt.Printf("\nthe flock did not answer: %v\n", err)
		return
	}
	online := 0
	for _, m := range reply.Members {
		if m.Online {
			online++
		}
	}
	fmt.Printf("\n%d of %d machines online, via %s\n", online, len(reply.Members), cl.Connector())
	for _, m := range reply.Members {
		mark := " "
		if m.Online {
			mark = "•"
		}
		fmt.Printf("  %s %-14s %s\n", mark, m.Name, m.Role)
	}
	if len(reply.Offers) > 0 {
		fmt.Printf("\n%d connector(s) waiting to register — run `ssheep master` to accept\n", len(reply.Offers))
	}
}

// watchFlock keeps accepting connectors and reporting joiners for a while, so
// pasting the two lines somewhere else has visible feedback here.
func watchFlock(rosterPath, flockKeyPath, nodeKeyPath, dir string, d time.Duration) error {
	fmt.Printf("\nwatching for %s — Ctrl-C when you are done\n", d)
	deadline := time.Now().Add(d)
	reported := map[string]bool{}
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)

		if pending, _ := master.PendingOffers(rosterPath, nodeKeyPath, ""); len(pending) > 0 {
			if _, err := master.AcceptOffers(rosterPath, flockKeyPath, nodeKeyPath, "", os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ssheep: %v\n", err)
			}
		}

		cl, err := open(dir, "")
		if err != nil {
			continue
		}
		reply, err := cl.List(8 * time.Second)
		cl.Close()
		if err != nil {
			continue
		}
		for _, m := range reply.Members {
			if m.Online && !reported[m.ID] {
				reported[m.ID] = true
				fmt.Printf("  👋 %s joined (%s)\n", m.Name, m.Role)
			}
		}
	}
	fmt.Printf("\nstopped watching. `ssheep see` shows the flock; `ssheep master` picks\nup any connector that registered meanwhile.\n")
	return nil
}
