// Command sshepard coordinates, controls and manages a flock of machines.
//
// One binary, one file, one key.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"sshepard.com/internal/connector"
	"sshepard.com/internal/flock"
	"sshepard.com/internal/invite"
	"sshepard.com/internal/netx"
	"sshepard.com/internal/sheep"
	"sshepard.com/internal/shepherd"
)

// version is stamped at build time.
var version = "dev"

const usage = `sshepard — one binary, one file, one key.

  init        create a new flock on this machine
  invite      mint a single-use invite for a new machine
  connector   run the address book and relay
  pin         print the fingerprint of a running connector
  sheep       join this machine to a flock, then serve
  see         show the flock, live
  run         run a command on one machine or on all of them
  forget      revoke a machine and remove it from the roster
  version     print the version

Run "sshepard <command> -h" for the flags of any command.`

func main() {
	log.SetFlags(0)
	log.SetPrefix("sshepard: ")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "invite":
		err = cmdInvite(args)
	case "connector":
		err = cmdConnector(args)
	case "pin":
		err = cmdPin(args)
	case "sheep":
		err = cmdSheep(args)
	case "see":
		err = cmdSee(args)
	case "run":
		err = cmdRun(args)
	case "forget":
		err = cmdForget(args)
	case "version", "-v", "--version":
		fmt.Println("sshepard", version)
		return
	case "help", "-h", "--help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "sshepard: unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshepard: %v\n", err)
		os.Exit(1)
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// state resolves the three files a machine keeps, honouring --dir.
func state(dir string) (roster, flockKey, nodeKey string) {
	if dir != "" {
		os.Setenv("SSHEPARD_DIR", dir)
	}
	return flock.DefaultRosterPath(), flock.DefaultFlockKeyPath(), flock.DefaultNodeKeyPath()
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func cmdInit(args []string) error {
	fs := newFlagSet("init")
	name := fs.String("name", "", "name of the flock (required)")
	me := fs.String("me", "", "name for this machine (default: its hostname)")
	dir := fs.String("dir", "", "where to keep keys and the roster (default ~/.sshepard)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("init: --name is required")
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)
	if _, err := os.Stat(rosterPath); err == nil {
		return fmt.Errorf("init: %s already exists — this machine already has a flock", rosterPath)
	}

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

	machineName := *me
	if machineName == "" {
		machineName, _ = os.Hostname()
	}
	kexPub, err := thisMachine.KexPub()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := flock.Roster{
		Version:  1,
		Name:     *name,
		FlockKey: authority.SignPub(),
		Members: []flock.Member{{
			ID:      flock.NodeID(thisMachine.SignPub()),
			Name:    machineName,
			Role:    flock.RoleShepherd,
			SignKey: thisMachine.SignPub(),
			KexKey:  kexPub,
			Added:   now,
		}},
		IssuedAt: now,
	}
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(rosterPath); err != nil {
		return err
	}

	fmt.Printf("created the flock %q\n\n", *name)
	fmt.Printf("  roster        %s\n", rosterPath)
	fmt.Printf("  authority key %s   <- keep this offline\n", flockKeyPath)
	fmt.Printf("  this machine  %s (%s)\n\n", machineName, r.Members[0].ID)
	fmt.Printf("next:\n")
	fmt.Printf("  1. on an always-on machine, run:  sshepard connector --listen :7000\n")
	fmt.Printf("  2. add it here:                   sshepard invite --name <machine> --connector <addr> --pin <fingerprint>\n")
	fmt.Printf("  3. add your first sheep:          sshepard invite --name pi\n")
	return nil
}

// ---------------------------------------------------------------------------
// invite
// ---------------------------------------------------------------------------

func cmdInvite(args []string) error {
	fs := newFlagSet("invite")
	name := fs.String("name", "", "name for the new machine (required)")
	role := fs.String("role", flock.RoleSheep, "sheep or shepherd")
	out := fs.String("out", "", "also write the invite to this file")
	connAddr := fs.String("connector", "", "add this connector (host:port) to the flock")
	connPin := fs.String("pin", "", `fingerprint of --connector, or "auto" to fetch it`)
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("invite: --name is required")
	}
	if *role != flock.RoleSheep && *role != flock.RoleShepherd {
		return fmt.Errorf("invite: --role must be %q or %q", flock.RoleSheep, flock.RoleShepherd)
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)

	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return fmt.Errorf("invite: %w (is this the shepherd machine?)", err)
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}

	if *connAddr != "" {
		pin := *connPin
		if pin == "auto" || pin == "" {
			fmt.Fprintf(os.Stderr, "sshepard: asking %s for its fingerprint...\n", *connAddr)
			pin, err = netx.FetchPin(*connAddr, 10*time.Second)
			if err != nil {
				return fmt.Errorf("invite: could not read the connector's fingerprint: %w", err)
			}
		}
		upsertConnector(&r, flock.Connector{Addr: *connAddr, Pin: pin})
		fmt.Printf("using connector %s (%s)\n", *connAddr, short(pin))
	} else if len(r.Connectors) == 0 {
		fmt.Fprintf(os.Stderr, "sshepard: note: this flock has no connector, so a new machine has nowhere to connect.\n")
		fmt.Fprintf(os.Stderr, "         add one with --connector <addr> --pin <fingerprint>.\n")
	}

	newMachine, err := flock.NewKeyFile()
	if err != nil {
		return err
	}
	kexPub, err := newMachine.KexPub()
	if err != nil {
		return err
	}
	id := flock.NodeID(newMachine.SignPub())
	member := flock.Member{
		ID:      id,
		Name:    *name,
		Role:    *role,
		SignKey: newMachine.SignPub(),
		KexKey:  kexPub,
		Added:   time.Now().UTC().Truncate(time.Second),
	}
	r.Upsert(member)
	r = r.Bump()
	sr, err = flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(rosterPath); err != nil {
		return err
	}
	publishRoster(rosterPath, nodeKeyPath)

	in := &invite.Invite{
		Version:  invite.Version,
		Roster:   *sr,
		NodeID:   id,
		Name:     *name,
		Role:     *role,
		SignSeed: newMachine.SignSeed,
		KexSeed:  newMachine.KexSeed,
	}
	blob, err := invite.Encode(in)
	if err != nil {
		return err
	}

	fmt.Printf("\nadded %q to the flock as a %s (%s)\n\n", *name, *role, id)
	if *out != "" {
		if err := invite.Save(*out, in); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n\n", *out)
		fmt.Printf("copy it to the new machine, put the sshepard binary there too, then run:\n\n")
		fmt.Printf("  sshepard sheep --invite-file %s\n\n", *out)
	}
	fmt.Printf("or paste this ticket directly on the new machine:\n\n")
	fmt.Printf("  sshepard sheep --invite '%s'\n\n", blob)
	fmt.Printf("the ticket carries that machine's private key, so hand it over privately.\n")
	fmt.Printf("undo it any time with:  sshepard forget --name %s\n", *name)
	return nil
}

func upsertConnector(r *flock.Roster, c flock.Connector) {
	for i := range r.Connectors {
		if r.Connectors[i].Addr == c.Addr {
			r.Connectors[i] = c
			return
		}
	}
	r.Connectors = append(r.Connectors, c)
	sort.Slice(r.Connectors, func(i, j int) bool { return r.Connectors[i].Addr < r.Connectors[j].Addr })
}

func short(pin string) string {
	if len(pin) <= 16 {
		return pin
	}
	return pin[:16] + "..."
}

// ---------------------------------------------------------------------------
// connector and pin
// ---------------------------------------------------------------------------

func cmdConnector(args []string) error {
	fs := newFlagSet("connector")
	listen := fs.String("listen", ":7000", "address to listen on")
	advertise := fs.String("advertise", "", "address others should use to reach this connector (default: as --listen)")
	dir := fs.String("dir", "", "where keys and the roster live")
	rosterFlag := fs.String("roster", "", "path to the roster")
	certFlag := fs.String("cert", "", "TLS certificate path")
	keyFlag := fs.String("key", "", "TLS key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rosterPath, _, _ := state(*dir)
	if *rosterFlag != "" {
		rosterPath = *rosterFlag
	}
	certPath, keyPath := *certFlag, *keyFlag
	if certPath == "" {
		certPath = flock.Dir() + "/connector.crt"
	}
	if keyPath == "" {
		keyPath = flock.Dir() + "/connector.key"
	}

	srv, err := connector.New(rosterPath, certPath, keyPath)
	if err != nil {
		return err
	}
	addr := *advertise
	if addr == "" {
		addr = advertiseAddr(*listen)
	}
	fmt.Printf("this connector's fingerprint:\n\n  %s\n\n", srv.Pin())
	fmt.Printf("add it to the flock from the shepherd machine with:\n\n")
	fmt.Printf("  sshepard invite --name <machine> --connector %s --pin %s\n\n", addr, srv.Pin())
	if addr == *listen {
		fmt.Printf("(set --advertise <host:port> if that is not the address others will use)\n\n")
	}
	return srv.ListenAndServe(*listen)
}

// advertiseAddr turns a listen address into something a remote machine could
// actually dial, so a fresh connector does not print ":7000" and leave the
// operator guessing.
func advertiseAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return listen
	}
	if ip := firstRoutableIP(); ip != "" {
		return net.JoinHostPort(ip, port)
	}
	if h, err := os.Hostname(); err == nil {
		return net.JoinHostPort(h, port)
	}
	return listen
}

func firstRoutableIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}

func cmdPin(args []string) error {
	fs := newFlagSet("pin")
	addr := fs.String("addr", "", "connector address, host:port (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("pin: --addr is required")
	}
	pin, err := netx.FetchPin(*addr, 10*time.Second)
	if err != nil {
		return err
	}
	fmt.Println(pin)
	return nil
}

// ---------------------------------------------------------------------------
// sheep
// ---------------------------------------------------------------------------

func cmdSheep(args []string) error {
	fs := newFlagSet("sheep")
	blob := fs.String("invite", "", "an invite ticket to install")
	file := fs.String("invite-file", "", "a path to an invite file to install")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	dir := fs.String("dir", "", "where keys and the roster live")
	installOnly := fs.Bool("install-only", false, "unpack the invite and exit, do not serve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rosterPath, _, nodeKeyPath := state(*dir)

	source := *file
	if source == "" {
		source = *blob
	}
	if source != "" {
		if err := sheep.Install(rosterPath, nodeKeyPath, source); err != nil {
			return err
		}
		fmt.Printf("installed %s\n", nodeKeyPath)
	}
	if _, err := os.Stat(nodeKeyPath); err != nil {
		return errors.New("sheep: this machine is not enrolled yet — pass --invite or --invite-file")
	}
	if *installOnly {
		return nil
	}
	return sheep.Run(rosterPath, nodeKeyPath, *conn)
}

// ---------------------------------------------------------------------------
// see, run, forget
// ---------------------------------------------------------------------------

func open(dir, conn string) (*shepherd.Client, error) {
	rosterPath, _, nodeKeyPath := state(dir)
	return shepherd.Open(rosterPath, nodeKeyPath, conn)
}

func cmdSee(args []string) error {
	fs := newFlagSet("see")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := open(*dir, *conn)
	if err != nil {
		return err
	}
	defer c.Close()

	members, err := c.List(10 * time.Second)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tROLE\tSTATUS\tID")
	online := 0
	for _, m := range members {
		status := "offline"
		if m.Online {
			status = "online"
			online++
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.Name, m.Role, status, m.ID)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("\n%d of %d machines online\n", online, len(members))
	return nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func cmdRun(args []string) error {
	fs := newFlagSet("run")
	var names stringList
	fs.Var(&names, "name", "a machine to run on (repeatable)")
	all := fs.Bool("all", false, "run on every sheep")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("run: no command given\n\n  sshepard run --all -- uptime")
	}

	c, err := open(*dir, *conn)
	if err != nil {
		return err
	}
	defer c.Close()

	targets := names
	if *all {
		targets = c.SheepNames()
		if len(targets) == 0 {
			return errors.New("run: there are no sheep in this flock yet")
		}
	}
	if len(targets) == 0 {
		return errors.New("run: name a machine with --name, or use --all")
	}
	return c.Run(targets, argv, os.Stdout)
}

func cmdForget(args []string) error {
	fs := newFlagSet("forget")
	name := fs.String("name", "", "the machine to revoke (required)")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("forget: --name is required")
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)

	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return fmt.Errorf("forget: %w (is this the shepherd machine?)", err)
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}
	if !r.Remove(*name) {
		return fmt.Errorf("forget: there is no machine called %q", *name)
	}
	r = r.Bump()
	sr, err = flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(rosterPath); err != nil {
		return err
	}
	publishRoster(rosterPath, nodeKeyPath)
	fmt.Printf("removed %q from the flock (roster is now version %d)\n", *name, r.Version)
	fmt.Printf("every connector will drop it within a couple of seconds.\n")
	return nil
}

// publishRoster pushes the roster to every connector in the flock. It is not an
// operator's job to copy the file around by hand.
func publishRoster(rosterPath, nodeKeyPath string) {
	pushed, err := shepherd.Publish(rosterPath, nodeKeyPath)
	switch {
	case err != nil && pushed == 0:
		fmt.Fprintf(os.Stderr, "sshepard: could not publish the roster: %v\n", err)
		fmt.Fprintf(os.Stderr, "sshepard: it will be picked up the next time a shepherd connects.\n")
	case err != nil:
		fmt.Printf("published the roster to %d connector(s); one refused: %v\n", pushed, err)
	case pushed > 0:
		fmt.Printf("published the roster to %d connector(s)\n", pushed)
	}
}
