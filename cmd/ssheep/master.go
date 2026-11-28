package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/invite"
	"ssheep.xyz/internal/local"
	"ssheep.xyz/internal/master"
	"ssheep.xyz/internal/netx"
)

// cmdMaster is the whole setup in one command: make a flock, hand out tickets,
// and print the one line per machine that turns a bare box into part of it.
//
// Everything here has a default, and the defaults are meant to work without
// being read. The flags exist for when they do not.
func cmdMaster(args []string) error {
	// The name is a positional, and the word "flock" in front of it is allowed
	// because that reads better out loud: `ssheep master flock "myflock"`.
	rest := args
	var words []string
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		words = append(words, rest[0])
		rest = rest[1:]
	}

	fs := newFlagSet("master")
	nameFlag := fs.String("name", "", "flock name")
	relay := fs.String("relay", defaultRelay, `public relay to start with ("" for none)`)
	private := fs.Bool("private", false, "no public relay: only connectors you run yourself")
	sheepN := fs.Int("sheep", defaultSheep, "how many sheep tickets to mint")
	connN := fs.Int("connector", defaultConnector, "how many connector tickets to mint")
	masterN := fs.Int("masters", defaultMasters, "how many spare master tickets to mint (a master ticket carries the flock key)")
	inviteMore := fs.Bool("invite", false, "mint fresh tickets for a flock that already exists")
	watch := fs.Duration("watch", 0, "keep watching for machines joining, e.g. --watch 3m")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	words = append(words, fs.Args()...)
	if len(words) > 0 && words[0] == "flock" {
		words = words[1:]
	}
	name := *nameFlag
	if name == "" && len(words) > 0 {
		name = words[0]
	}
	if name == "" {
		return errors.New(`master: name the flock

  ssheep master flock "myflock"`)
	}
	if *private {
		*relay = ""
	}

	f, err := local.Resolve(name)
	created := false
	switch {
	case err == nil:
		// Already here. Carry on from where it is.
	case strings.Contains(err.Error(), "no flock"):
		f, err = local.Create(name)
		if err != nil {
			return err
		}
		created = true
	default:
		return err
	}

	if created {
		fmt.Printf("👑  You are Master — flock %q created\n", f.Name)
		if *relay != "" {
			if err := addRelay(f, *relay); err != nil {
				fmt.Fprintf(os.Stderr, "ssheep: %v\n", err)
			}
		}
	} else {
		fmt.Printf("👑  You are a master of flock %q\n", f.Name)
	}

	if f.Mastered() {
		acceptOffers(f)
	}
	if created || *inviteMore {
		if err := printTickets(f, *sheepN, *connN, *masterN); err != nil {
			return err
		}
	}
	report(f)

	if *watch > 0 {
		return watchFlock(f, *watch)
	}
	return nil
}

// addRelay puts the project's public relay into a fresh flock, so the flock
// works before its owner has run a connector of their own.
func addRelay(f *local.Flock, addr string) error {
	pin, err := netx.FetchPin(addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("%s did not answer, so the flock starts with no connector yet.\n  run a connector and it will register itself", addr)
	}
	authority, err := f.Authority()
	if err != nil {
		return err
	}
	r := f.Roster
	r.UpsertConnector(flock.Connector{Addr: addr, Pin: pin})
	r = r.Bump()
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(f.RosterPath); err != nil {
		return err
	}
	fmt.Printf("    relay      %s\n", addr)
	return nil
}

// printTickets mints the tickets and prints one line per machine to paste.
func printTickets(f *local.Flock, sheepN, connN, masterN int) error {
	blocks := []struct {
		n    int
		role string
		head string
	}{
		{sheepN, flock.RoleSheep, "🐑 run this on every machine you want in the flock"},
		{connN, flock.RoleConnector, "📡 run this on a machine you want to relay and do nothing else:"},
		{masterN, flock.RoleMaster, "👑 run this on each machine you want to be a Master 👑"},
	}
	for _, b := range blocks {
		if b.n <= 0 {
			continue
		}
		fmt.Printf("\n%s:\n\n", b.head)
		for i := 1; i <= b.n; i++ {
			blob, err := mintInvite(f.Name, fmt.Sprintf("%s-%d", b.role, i), b.role)
			if err != nil {
				return err
			}
			fmt.Printf("  %s\n", ticketLine(blob))
		}
	}
	fmt.Printf("\nEach ticket works once, on one machine, and carries that machine's private key.\n")
	fmt.Printf("Machines relay for the flock on their own when they can be reached, so there is\n")
	fmt.Printf("nothing to work out and no machine to pick.\n")
	if masterN > 0 {
		fmt.Printf("A master ticket also carries the flock key — the authority to add and remove\n")
		fmt.Printf("machines. Keep those lines as safe as this machine.\n")
	}
	if sheepN > 0 {
		fmt.Printf("Unused ones can be dropped again with `ssheep forget %q --name sheep-%d`.\n", f.Name, sheepN)
	}
	fmt.Printf("More anytime with `ssheep master %q --invite`.\n", f.Name)
	return nil
}

// ticketLine is the whole of onboarding in one line: install, then join. It is
// printed rather than described so it can be copied onto a machine that has
// nothing on it at all.
//
// The installer does the joining, by full path, so it does not matter whether
// the directory it chose is on that machine's PATH. The role is not named here
// because the ticket carries it: nobody has to choose right, and nobody can
// choose wrong.
func ticketLine(blob string) string {
	return fmt.Sprintf("curl -fsSL %s | sh -s -- --ticket %q", joinURL, blob)
}

// uniqueName keeps roster names distinct. Minting twice used to be able to
// produce two machines called "sheep-1", which made `forget --name` a guess.
func uniqueName(r flock.Roster, name string) string {
	if r.FindByName(name) == nil {
		return name
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", name, i)
		if r.FindByName(cand) == nil {
			return cand
		}
	}
}

// mintInvite adds a member to a flock and returns the ticket for it. It reloads
// the flock each time, because every mint bumps the roster.
func mintInvite(flockName, name, role string) (string, error) {
	f, err := local.Resolve(flockName)
	if err != nil {
		return "", err
	}
	authority, err := f.Authority()
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
	r := f.Roster
	name = uniqueName(r, name)
	r.Upsert(flock.Member{
		ID:      id,
		Name:    name,
		Role:    role,
		SignKey: machine.SignPub(),
		KexKey:  kex,
		Added:   time.Now().UTC().Truncate(time.Second),
		// Every machine may relay. Whether it can is a question only the network
		// can answer, so the machine tries and the master checks -- which is why
		// nobody has to work out which box has a public address.
		Relay: true,
	})
	r = r.Bump()
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return "", err
	}
	if err := sr.Save(f.RosterPath); err != nil {
		return "", err
	}
	in := &invite.Invite{
		Version:  invite.Version,
		Roster:   *sr,
		NodeID:   id,
		Name:     name,
		Role:     role,
		SignSeed: machine.SignSeed,
		KexSeed:  machine.KexSeed,
	}
	if role == flock.RoleMaster {
		in.Flock = authority
	}
	return invite.Encode(in)
}

// acceptOffers takes on any machine that has registered itself since last time.
//
// It runs on every `master` command rather than only when something looks
// waiting, because a machine that moved offers a new address that looks like
// nothing new until the old one is found to be dead -- and only AcceptOffers can
// make that call.
func acceptOffers(f *local.Flock) {
	if pending, _ := master.PendingOffers(f.RosterPath, f.NodePath, ""); len(pending) > 0 {
		fmt.Printf("\nmachines offering to relay in flock %q:\n", f.Name)
	}
	if _, err := master.AcceptOffers(f.RosterPath, f.KeyPath, f.NodePath, "", maxRelays, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ssheep: %v\n", err)
	}
}

// report prints where a flock stands, without failing if it cannot be reached.
func report(f *local.Flock) {
	// Reload: accepting offers above may just have added a relay.
	if sr, err := flock.LoadSignedRoster(f.RosterPath); err == nil {
		if r, err := sr.Verify(); err == nil {
			f.Roster = r
		}
	}
	reply, answered, err := master.ListAll(f.RosterPath, f.NodePath, "", 10*time.Second)
	if err != nil && len(answered) == 0 {
		fmt.Printf("\nnot reachable from here right now: %v\n", err)
		fmt.Printf("it keeps trying; `ssheep see` shows the flock once a relay answers.\n")
		return
	}
	online := 0
	for _, m := range reply.Members {
		if m.Online {
			online++
		}
	}
	fmt.Printf("\nflock %q — %d of %d machines online, via %d relay(s)\n", f.Name, online, len(reply.Members), len(answered))
	relays := relaysByMember(f.Roster)
	for _, m := range reply.Members {
		mark := " "
		if m.Online {
			mark = "•"
		}
		role := m.Role
		if addr, ok := relays[m.ID]; ok {
			role = m.Role + "  relaying at " + addr
		}
		fmt.Printf("  %s %-14s %s\n", mark, m.Name, role)
	}
	if n := len(waitingMachines(reply.Offers, f.Roster)); n > 0 {
		fmt.Printf("\n%d machine(s) offered to relay but cannot be reached from here — they stay sheep\n", n)
	}
}

// watchFlock keeps accepting connectors and reporting joiners for a while, so
// pasting the lines somewhere else has visible feedback here.
func watchFlock(f *local.Flock, d time.Duration) error {
	fmt.Printf("\nwatching flock %q for %s — Ctrl-C when you are done\n", f.Name, d)
	deadline := time.Now().Add(d)
	reported := map[string]bool{}
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)

		if f.Mastered() {
			if pending, _ := master.PendingOffers(f.RosterPath, f.NodePath, ""); len(pending) > 0 {
				if _, err := master.AcceptOffers(f.RosterPath, f.KeyPath, f.NodePath, "", maxRelays, os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "ssheep: %v\n", err)
				}
			}
		}

		cl, err := master.Open(f.RosterPath, f.NodePath, "")
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
	fmt.Printf("\nstopped watching. `ssheep see` shows the flock.\n")
	return nil
}
