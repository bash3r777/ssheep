// Command ssheep coordinates, controls and manages a flock of machines.
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
	"strings"
	"text/tabwriter"
	"time"

	"ssheep.xyz/internal/connector"
	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/invite"
	"ssheep.xyz/internal/netx"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/sheep"
	"ssheep.xyz/internal/master"
)

// version is stamped at build time.
var version = "dev"

// The opinionated defaults. Everything below can be overridden; none of it has
// to be, which is the point.
const (
	// defaultRelay is the public relay a new flock starts with, so that a flock
	// works before its owner has run a single connector.
	defaultRelay = "relay.ssheep.xyz:7000"
	// defaultPort is what a connector listens on.
	defaultPort = 7000
	// defaultSheep is how many sheep tickets `ssheep master` mints up front.
	defaultSheep = 3
)

const usage = `ssheep — one binary, one file, one key.

  master                 set up a whole flock: one command, then paste two lines
  sheep "<ticket>"       turn this machine into a sheep
  connector "<ticket>"   turn this machine into a connector

  see                    show the flock, live
  run                    run a command on one machine or on all of them
  forget                 revoke a machine and remove it from the roster

  init, invite           the same thing step by step, when you want control
  connector              run a relay with no flock of its own
  connector add          register a connector by hand
  connector remove       forget one
  connector list         show them, and whether they answer
  pin                    print the fingerprint of a running connector

  version                print the version

Run "ssheep <command> -h" for the flags of any command.`

func main() {
	log.SetFlags(0)
	log.SetPrefix("ssheep: ")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "master":
		err = cmdMaster(args)
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
		fmt.Println("ssheep", version)
		return
	case "help", "-h", "--help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "ssheep: unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssheep: %v\n", err)
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
		os.Setenv("SSHEEP_DIR", dir)
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
	dir := fs.String("dir", "", "where to keep keys and the roster (default ~/.ssheep)")
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
			Role:    flock.RoleMaster,
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
	fmt.Printf("  the easy way is one command:\n\n")
	fmt.Printf("      ssheep master      mints the tickets and prints the two lines to paste\n\n")
	fmt.Printf("  or go step by step:\n")
	fmt.Printf("      1. on a machine with a public address:  ssheep connector\n")
	fmt.Printf("      2. register it here:                    ssheep connector add --addr <host:port>\n")
	fmt.Printf("      3. add your first sheep:                ssheep invite --name pi\n")
	fmt.Printf("\nadd a second connector early: with only one, its bad day is the flock's bad day.\n")
	return nil
}

// ---------------------------------------------------------------------------
// invite
// ---------------------------------------------------------------------------

func cmdInvite(args []string) error {
	fs := newFlagSet("invite")
	name := fs.String("name", "", "name for the new machine (required)")
	role := fs.String("role", flock.RoleSheep, "sheep or master")
	out := fs.String("out", "", "also write the invite to this file")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("invite: --name is required")
	}
	if *role != flock.RoleSheep && *role != flock.RoleMaster && *role != flock.RoleConnector {
		return fmt.Errorf("invite: --role must be %q, %q or %q", flock.RoleSheep, flock.RoleMaster, flock.RoleConnector)
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)

	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return fmt.Errorf("invite: %w (is this the master machine?)", err)
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}

	if len(r.Connectors) == 0 {
		fmt.Fprintf(os.Stderr, "ssheep: note: this flock has no connector, so a new machine has nowhere to connect.\n")
		fmt.Fprintf(os.Stderr, "         add one with: ssheep connector add --addr <host:port>\n")
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
		fmt.Printf("copy it to the new machine, put the ssheep binary there too, then run:\n\n")
		fmt.Printf("  ssheep sheep --invite-file %s\n\n", *out)
	}
	fmt.Printf("or paste this ticket directly on the new machine:\n\n")
	fmt.Printf("  ssheep sheep --invite '%s'\n\n", blob)
	fmt.Printf("the ticket carries that machine's private key, so hand it over privately.\n")
	fmt.Printf("undo it any time with:  ssheep forget --name %s\n", *name)
	return nil
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
	if len(args) > 0 {
		switch args[0] {
		case "add":
			return cmdConnectorAdd(args[1:])
		case "remove":
			return cmdConnectorRemove(args[1:])
		case "list":
			return cmdConnectorList(args[1:])
		}
		// A ticket as the first argument means "join the flock as a connector".
		if !strings.HasPrefix(args[0], "-") {
			return cmdConnectorJoin(args)
		}
	}
	// No ticket. If this machine is already enrolled as a connector, carry on
	// being one — a restart should not turn it into something else. Otherwise
	// run a plain relay with no flock of its own.
	if enrolledRole(argValue(args, "dir")) == flock.RoleConnector {
		return cmdConnectorJoin(args)
	}
	fs := newFlagSet("connector")
	listen := fs.String("listen", ":7000", "address to listen on")
	advertise := fs.String("advertise", "", "address others should use to reach this connector (default: as --listen)")
	dir := fs.String("dir", "", "where keys and the roster live")
	rosterFlag := fs.String("roster", "", "path to a roster to serve from startup")
	certFlag := fs.String("cert", "", "TLS certificate path")
	keyFlag := fs.String("key", "", "TLS key path")
	public := fs.Bool("public", false, "serve any flock that can prove itself, not only your own")
	maxFlocks := fs.Int("max-flocks", 100, "refuse new flocks beyond this many (0 = no limit)")
	maxConns := fs.Int("max-conns", 2000, "refuse new connections beyond this many (0 = no limit)")
	maxMembers := fs.Int("max-members", 1000, "refuse a roster with more members than this (0 = no limit)")
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

	srv, err := connector.New(connector.Config{
		RosterPath: rosterPath,
		CertPath:   certPath,
		KeyPath:    keyPath,
		Public:     *public,
		MaxFlocks:  *maxFlocks,
		MaxConns:   *maxConns,
		MaxMembers: *maxMembers,
	})
	if err != nil {
		return err
	}
	addr := *advertise
	if addr == "" {
		addr = advertiseAddr(*listen)
	}
	fmt.Printf("this connector's fingerprint:\n\n  %s\n\n", srv.Pin())
	if *public {
		fmt.Printf("this connector is public: it will serve any flock whose roster proves itself,\n")
		fmt.Printf("within %d flock(s) and %d connection(s). It never sees what it carries.\n\n", *maxFlocks, *maxConns)
	} else {
		fmt.Printf("this connector serves only the flock it was given. Add --public to serve any flock\n")
		fmt.Printf("that can prove itself, which is what a community relay does.\n\n")
	}
	fmt.Printf("add it to the flock from the master machine with:\n\n")
	fmt.Printf("  ssheep connector add --addr %s\n\n", addr)
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

// cmdConnectorJoin turns this machine into a connector for its flock: it starts
// a relay and tells the other connectors where it is, so nobody has to carry an
// address or a fingerprint to the master by hand.
func cmdConnectorJoin(args []string) error {
	fs := newFlagSet("connector")
	addr := fs.String("addr", "", "the address other machines will reach this one at\n(set it if the guess is wrong; the guess is what this machine looks like from outside)")
	port := fs.Int("port", defaultPort, "port to listen on")
	public := fs.Bool("public", false, "also serve flocks that are not yours")
	file := fs.String("ticket-file", "", "read the ticket from a file instead of the command line")
	installOnly := fs.Bool("install-only", false, "unpack the ticket and exit, do not serve")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rosterPath, _, nodeKeyPath := state(*dir)

	source := fs.Arg(0)
	if source == "" {
		source = *file
	}
	if source != "" {
		if err := invite.Install(rosterPath, nodeKeyPath, source); err != nil {
			return err
		}
		fmt.Println("📡  this machine is enrolled as a connector")
	}
	if _, err := os.Stat(nodeKeyPath); err != nil {
		return errors.New(`connector: this machine is not enrolled yet

  run:  ssheep connector "<ticket>"   (the ticket is printed by ` + "`ssheep master`" + `)`)
	}
	if *installOnly {
		return nil
	}
	return connector.Join(rosterPath, nodeKeyPath, *addr, *port, *public)
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

// cmdConnectorAdd registers a connector in the flock and publishes the roster.
//
// More than one connector is not redundancy for its own sake: with a single one,
// that machine's bad afternoon is the flock's bad afternoon.
func cmdConnectorAdd(args []string) error {
	fs := newFlagSet("connector add")
	addr := fs.String("addr", "", "the connector's address, host:port (required)")
	pin := fs.String("pin", "auto", `its fingerprint, or "auto" to read it from the connector`)
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("connector add: --addr is required")
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)

	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return fmt.Errorf("connector add: %w (is this the master machine?)", err)
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}

	p := *pin
	if p == "auto" || p == "" {
		fmt.Fprintf(os.Stderr, "ssheep: asking %s for its fingerprint...\n", *addr)
		p, err = netx.FetchPin(*addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("connector add: could not reach %s: %w\n  start it first, or pass --pin <fingerprint>", *addr, err)
		}
	}

	// Ask it to serve this flock before writing it down. A connector that would
	// refuse us is worse than no connector at all: it would sit in the roster
	// looking like redundancy we do not actually have.
	nodeKey, err := flock.LoadKeyFile(nodeKeyPath)
	if err != nil {
		return fmt.Errorf("connector add: %w", err)
	}
	probe := peer.Identity{
		Flock:  r.ID(),
		NodeID: flock.NodeID(nodeKey.SignPub()),
		Key:    nodeKey.SignKey(),
		Roster: sr,
	}
	conn, err := peer.Dial(*addr, p, probe, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connector add: %s will not serve this flock: %w\n  if it is yours, start it with --public, or give it this flock's roster", *addr, err)
	}
	conn.Close()

	replacing := false
	for _, c := range r.Connectors {
		if c.Addr == *addr {
			replacing = true
		}
	}
	r.UpsertConnector(flock.Connector{Addr: *addr, Pin: p})
	r = r.Bump()
	sr, err = flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(rosterPath); err != nil {
		return err
	}
	if replacing {
		fmt.Printf("updated connector %s (%s)\n", *addr, short(p))
	} else {
		fmt.Printf("added connector %s (%s) — the flock now has %d\n", *addr, short(p), len(r.Connectors))
	}
	publishRoster(rosterPath, nodeKeyPath)
	return nil
}

func cmdConnectorRemove(args []string) error {
	fs := newFlagSet("connector remove")
	addr := fs.String("addr", "", "the connector's address (required)")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("connector remove: --addr is required")
	}
	rosterPath, flockKeyPath, nodeKeyPath := state(*dir)

	authority, err := flock.LoadKeyFile(flockKeyPath)
	if err != nil {
		return fmt.Errorf("connector remove: %w (is this the master machine?)", err)
	}
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}
	if !r.RemoveConnector(*addr) {
		return fmt.Errorf("connector remove: %s is not a connector for this flock", *addr)
	}
	r = r.Bump()
	sr, err = flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(rosterPath); err != nil {
		return err
	}
	fmt.Printf("removed connector %s — %d left\n", *addr, len(r.Connectors))
	if len(r.Connectors) == 0 {
		fmt.Fprintf(os.Stderr, "ssheep: warning: this flock now has no connector, so its machines have nowhere to meet.\n")
	}
	// The removed connector is no longer in the roster, so it is not among the
	// machines we publish to. The rest still need to hear about it.
	publishRoster(rosterPath, nodeKeyPath)
	return nil
}

func cmdConnectorList(args []string) error {
	fs := newFlagSet("connector list")
	dir := fs.String("dir", "", "where keys and the roster live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rosterPath, _, _ := state(*dir)
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return err
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}
	if len(r.Connectors) == 0 {
		fmt.Println("this flock has no connector, so its machines have nowhere to meet")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ADDRESS\tSTATUS\tFINGERPRINT")
	for _, c := range r.Connectors {
		status := "unreachable"
		if got, err := netx.FetchPin(c.Addr, 3*time.Second); err == nil {
			switch got {
			case c.Pin:
				status = "up"
			default:
				status = "FINGERPRINT CHANGED"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.Addr, status, short(c.Pin))
	}
	_ = w.Flush()
	fmt.Printf("\nmachines try these in order, so the first is the preferred one\n")
	return nil
}

// ---------------------------------------------------------------------------
// sheep
// ---------------------------------------------------------------------------

func cmdSheep(args []string) error {
	fs := newFlagSet("sheep")
	file := fs.String("ticket-file", "", "read the ticket from a file instead of the command line")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	dir := fs.String("dir", "", "where keys and the roster live")
	installOnly := fs.Bool("install-only", false, "unpack the ticket and exit, do not serve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rosterPath, _, nodeKeyPath := state(*dir)

	source := fs.Arg(0)
	if source == "" {
		source = *file
	}
	if source != "" {
		if err := invite.Install(rosterPath, nodeKeyPath, source); err != nil {
			return err
		}
		fmt.Println("🐑  this machine is in the flock")
	}
	if _, err := os.Stat(nodeKeyPath); err != nil {
		return errors.New(`sheep: this machine is not enrolled yet

  run:  ssheep sheep "<ticket>"     (the ticket is printed by ` + "`ssheep master`" + `)`)
	}
	if *installOnly {
		return nil
	}
	return sheep.Run(rosterPath, nodeKeyPath, *conn)
}

// ---------------------------------------------------------------------------
// see, run, forget
// ---------------------------------------------------------------------------

func open(dir, conn string) (*master.Client, error) {
	rosterPath, _, nodeKeyPath := state(dir)
	return master.Open(rosterPath, nodeKeyPath, conn)
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

	reply, err := c.List(10 * time.Second)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tROLE\tSTATUS\tID")
	online := 0
	for _, m := range reply.Members {
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
	fmt.Printf("\n%d of %d machines online\n", online, len(reply.Members))
	if reply.Name != "" {
		fmt.Printf("flock %q (%s)\n", reply.Name, reply.Flock)
	}
	if n := len(c.Connectors()); n > 1 {
		fmt.Printf("via %s (of %d connectors)\n", c.Connector(), n)
	}
	if len(reply.Offers) > 0 {
		fmt.Printf("\n%d connector(s) waiting to register — run `ssheep master` to accept\n", len(reply.Offers))
	}
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
		return errors.New("run: no command given\n\n  ssheep run --all -- uptime")
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
		return fmt.Errorf("forget: %w (is this the master machine?)", err)
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
	pushed, err := master.Publish(rosterPath, nodeKeyPath)
	switch {
	case err != nil && pushed == 0:
		fmt.Fprintf(os.Stderr, "ssheep: could not publish the roster: %v\n", err)
		fmt.Fprintf(os.Stderr, "ssheep: it will be picked up the next time a master connects.\n")
	case err != nil:
		fmt.Printf("published the roster to %d connector(s); one refused: %v\n", pushed, err)
	case pushed > 0:
		fmt.Printf("published the roster to %d connector(s)\n", pushed)
	}
}
