// Command ssheep coordinates, controls and manages a flock of machines.
//
// One binary, one file, one key. A machine can be in as many flocks as it likes.
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
	"ssheep.xyz/internal/local"
	"ssheep.xyz/internal/master"
	"ssheep.xyz/internal/netx"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/sheep"
)

// version is stamped at build time.
var version = "dev"

// The opinionated defaults. Everything here can be overridden; none of it has to
// be, which is the point.
const (
	// defaultRelay is the public relay a new flock starts with, so a flock works
	// before its owner has run a connector of their own.
	defaultRelay = "relay.ssheep.xyz:7000"
	// defaultPort is what a connector listens on.
	defaultPort = 7000
	// defaultSheep and defaultConnector are how many tickets `master` mints.
	defaultSheep     = 3
	defaultConnector = 1
	// defaultMasters is how many spare master tickets it mints. One, because a
	// flock whose key exists in exactly one place is a flock that cannot be
	// changed the day that place dies — and a master ticket is only as safe as
	// the line it is printed on.
	defaultMasters = 1
	// joinURL is the one-liner that installs the binary, so a ticket can be a
	// single line somebody pastes onto a machine that has nothing on it.
	joinURL = "https://ssheep.xyz/install.sh"
)

const usage = `ssheep — one binary, one file, one key.

  master [flock] <name>      create a flock, print what to run on the others
  join "<ticket>"            take a ticket somebody gave you, and be what it says
  sheep "<ticket>"           join a flock as a sheep, then serve
  connector "<ticket>"       join a flock as a connector, then serve

  see [<flock>]              the flocks, live
  run <flock> -- <cmd>       run a command on every sheep in a flock
  shell <flock> --name N     open a shell on one machine
  forget <flock> --name N    revoke a machine
  flock list                 the flocks this machine knows

  invite <flock> --name N    mint one ticket by hand
  connector add|remove|list  manage a flock's connectors by hand
  pin --addr HOST:PORT       print a connector's fingerprint

  version                    print the version

A machine can be in as many flocks as it likes, and holds a separate key in
each one. Run "ssheep <command> -h" for the flags of any command.`

func main() {
	log.SetFlags(0)
	log.SetPrefix("ssheep: ")

	args := extractDir(os.Args[1:])
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]

	var err error
	switch cmd {
	case "master":
		err = cmdMaster(rest)
	case "join":
		err = cmdJoin(rest)
	case "sheep":
		err = cmdSheep(rest)
	case "connector":
		err = cmdConnector(rest)
	case "see":
		err = cmdSee(rest)
	case "run":
		err = cmdRun(rest)
	case "shell":
		err = cmdShell(rest)
	case "forget":
		err = cmdForget(rest)
	case "invite":
		err = cmdInvite(rest)
	case "flock":
		err = cmdFlock(rest)
	case "pin":
		err = cmdPin(rest)
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

// extractDir keeps `--dir <path>` working. It used to be a flag on every
// command; now the one place a machine's state is chosen is $SSHEEP_DIR, which
// is what systemd units set. Accepted here so units written for the older
// command line keep running after the binary is replaced.
func extractDir(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "--dir" || a == "-dir") && i+1 < len(args):
			os.Setenv("SSHEEP_DIR", args[i+1])
			i++
		case strings.HasPrefix(a, "--dir="):
			os.Setenv("SSHEEP_DIR", strings.TrimPrefix(a, "--dir="))
		case strings.HasPrefix(a, "-dir="):
			os.Setenv("SSHEEP_DIR", strings.TrimPrefix(a, "-dir="))
		default:
			out = append(out, a)
		}
	}
	return out
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parseFlags parses flags that may sit before or after the positional
// arguments. Go's flag package stops at the first non-flag, which would silently
// drop `--install-only` in `ssheep connector "<ticket>" --install-only` — and
// that is exactly how the printed one-liners and the systemd units call it. It
// returns the positionals, in order.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// sheepTargets is every flock this machine is a sheep in.
func sheepTargets() ([]sheep.Target, error) {
	flocks, err := local.WithRole(flock.RoleSheep)
	if err != nil {
		return nil, err
	}
	out := make([]sheep.Target, 0, len(flocks))
	for _, f := range flocks {
		out = append(out, sheep.Target{Name: f.Name, RosterPath: f.RosterPath, NodePath: f.NodePath})
	}
	return out, nil
}

// connectorTargets is every flock this machine is a connector for.
func connectorTargets() ([]connector.Enrolled, error) {
	flocks, err := local.WithRole(flock.RoleConnector)
	if err != nil {
		return nil, err
	}
	out := make([]connector.Enrolled, 0, len(flocks))
	for _, f := range flocks {
		out = append(out, connector.Enrolled{Name: f.Name, RosterPath: f.RosterPath, NodePath: f.NodePath})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// join
// ---------------------------------------------------------------------------

// cmdJoin is what the printed one-liner runs once the binary is installed.
//
// The role is taken from the ticket rather than named on the command line, so
// there is one line to hand out per machine and no way to paste the wrong verb.
// A master ticket leaves a machine that holds the flock key, and a master is
// something you sit down at rather than something that serves, so that one
// installs and reports instead of running.
func cmdJoin(args []string) error {
	fs := newFlagSet("join")
	ticket := fs.String("ticket", "", "the ticket, if it is not the argument")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	addr := fs.String("addr", "", "connector: the address other machines reach this one at")
	port := fs.Int("port", defaultPort, "connector: port to listen on")
	public := fs.Bool("public", false, "connector: also serve flocks that are not yours")
	installOnly := fs.Bool("install-only", false, "take the ticket and exit, do not serve")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	source := *ticket
	if source == "" && len(pos) > 0 {
		source = pos[0]
	}
	if source == "" {
		return errors.New(`join: no ticket

  ssheep join "<ticket>"     the line somebody gave you does this for you`)
	}
	in, err := invite.Resolve(source)
	if err != nil {
		return err
	}
	roster, err := in.Validate()
	if err != nil {
		return err
	}
	f, err := local.Install(source)
	if err != nil {
		// Already enrolled. That is a restart, not a first join — the same
		// command has to work both times, or a service unit cannot use it.
		existing, oerr := local.Resolve(roster.Name)
		if oerr != nil {
			return err
		}
		f = existing
	}
	if *installOnly {
		fmt.Printf("%s  this machine took the ticket for %q\n", roleMark(f.Role), f.Name)
		return nil
	}

	switch f.Role {
	case flock.RoleMaster:
		fmt.Printf("👑  this machine is now a master of flock %q\n", f.Name)
		fmt.Printf("    the flock key is at %s — back it up, and keep it off sheep\n", f.KeyPath)
		fmt.Printf("    try:  ssheep see %q   ·   ssheep master %q --invite\n", f.Name, f.Name)
		return nil
	case flock.RoleSheep:
		fmt.Printf("🐑  this machine is now a sheep in flock %q\n", f.Name)
		targets, err := sheepTargets()
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return errors.New("join: the ticket was taken, but this machine is not a sheep in any flock")
		}
		return sheep.RunMany(targets, *conn)
	case flock.RoleConnector:
		fmt.Printf("📡  this machine is now a connector for flock %q\n", f.Name)
		enrolled, err := connectorTargets()
		if err != nil {
			return err
		}
		if len(enrolled) == 0 {
			return errors.New("join: the ticket was taken, but this machine is not a connector for any flock")
		}
		return connector.Join(enrolled, *addr, *port, *public)
	default:
		return fmt.Errorf("join: this ticket says %q, which this build does not know", f.Role)
	}
}

// ---------------------------------------------------------------------------
// sheep
// ---------------------------------------------------------------------------

func cmdSheep(args []string) error {
	fs := newFlagSet("sheep")
	file := fs.String("ticket-file", "", "read the ticket from a file instead of the command line")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	installOnly := fs.Bool("install-only", false, "unpack the ticket and exit, do not serve")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	source := ""
	if len(pos) > 0 {
		source = pos[0]
	}
	if source == "" {
		source = *file
	}
	if source != "" {
		f, err := local.Install(source)
		if err != nil {
			return err
		}
		fmt.Printf("🐑  this machine is now a sheep in flock %q\n", f.Name)
	}
	targets, err := sheepTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New(`sheep: this machine is not a sheep in any flock

  run:  ssheep sheep "<ticket>"    (printed by ` + "`ssheep master`" + `)`)
	}
	if *installOnly {
		return nil
	}
	return sheep.RunMany(targets, *conn)
}

// ---------------------------------------------------------------------------
// connector
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
		if !strings.HasPrefix(args[0], "-") {
			return cmdConnectorJoin(args)
		}
	}
	// No ticket. If this machine is already a connector for something, carry on
	// being one; otherwise run a plain relay that serves flocks it is given.
	if enrolled, err := connectorTargets(); err == nil && len(enrolled) > 0 {
		return cmdConnectorJoin(args)
	}
	return cmdPlainRelay(args)
}

// cmdConnectorJoin turns this machine into a connector for every flock it is
// enrolled in as one, and starts a relay that serves them.
func cmdConnectorJoin(args []string) error {
	fs := newFlagSet("connector")
	addr := fs.String("addr", "", "the address other machines will reach this one at\n(only if the guess is wrong; the guess is what this machine looks like from outside)")
	port := fs.Int("port", defaultPort, "port to listen on")
	public := fs.Bool("public", false, "also serve flocks that are not yours")
	file := fs.String("ticket-file", "", "read the ticket from a file instead of the command line")
	installOnly := fs.Bool("install-only", false, "unpack the ticket and exit, do not serve")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	source := ""
	if len(pos) > 0 {
		source = pos[0]
	}
	if source == "" {
		source = *file
	}
	if source != "" {
		f, err := local.Install(source)
		if err != nil {
			return err
		}
		fmt.Printf("📡  this machine is now a connector for flock %q\n", f.Name)
	}
	enrolled, err := connectorTargets()
	if err != nil {
		return err
	}
	if len(enrolled) == 0 {
		return errors.New(`connector: this machine is not a connector for any flock

  run:  ssheep connector "<ticket>"   (printed by ` + "`ssheep master`" + `)`)
	}
	if *installOnly {
		return nil
	}
	return connector.Join(enrolled, *addr, *port, *public)
}

// cmdPlainRelay runs a relay with no flock of its own: the thing a donated
// connector is.
func cmdPlainRelay(args []string) error {
	fs := newFlagSet("connector")
	listen := fs.String("listen", fmt.Sprintf(":%d", defaultPort), "address to listen on")
	advertise := fs.String("advertise", "", "address others should use to reach this connector (default: as --listen)")
	var rosters stringList
	fs.Var(&rosters, "roster", "a roster to serve from startup (repeatable)")
	certFlag := fs.String("cert", "", "TLS certificate path")
	keyFlag := fs.String("key", "", "TLS key path")
	public := fs.Bool("public", false, "serve any flock that can prove itself, not only your own")
	maxFlocks := fs.Int("max-flocks", 100, "refuse new flocks beyond this many (0 = no limit)")
	maxConns := fs.Int("max-conns", 2000, "refuse new connections beyond this many (0 = no limit)")
	maxMembers := fs.Int("max-members", 1000, "refuse a roster with more members than this (0 = no limit)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	certPath, keyPath := *certFlag, *keyFlag
	if certPath == "" {
		certPath = flock.Dir() + "/connector.crt"
	}
	if keyPath == "" {
		keyPath = flock.Dir() + "/connector.key"
	}
	srv, err := connector.New(connector.Config{
		RosterPaths: rosters,
		CertPath:    certPath,
		KeyPath:     keyPath,
		Public:      *public,
		MaxFlocks:   *maxFlocks,
		MaxConns:    *maxConns,
		MaxMembers:  *maxMembers,
	})
	if err != nil {
		return err
	}
	addr := *advertise
	if addr == "" {
		addr = advertiseAddr(*listen)
	}
	fmt.Printf("this connector's fingerprint:\n\n  %s\n\n", srv.Pin())
	fmt.Printf("add it to a flock from the master machine with:\n\n")
	fmt.Printf("  ssheep connector add --flock <flock> --addr %s\n\n", addr)
	if *public {
		fmt.Printf("this connector is public: it will serve any flock whose roster proves itself.\n")
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

func cmdConnectorAdd(args []string) error {
	fs := newFlagSet("connector add")
	flockName := fs.String("flock", "", "which flock (required)")
	addr := fs.String("addr", "", "the connector's address, host:port (required)")
	pin := fs.String("pin", "auto", `its fingerprint, or "auto" to read it from the connector`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *flockName == "" || *addr == "" {
		return errors.New("connector add: --flock and --addr are required")
	}
	f, err := local.Resolve(*flockName)
	if err != nil {
		return err
	}
	authority, err := f.Authority()
	if err != nil {
		return err
	}
	key, err := f.Key()
	if err != nil {
		return err
	}
	r := f.Roster

	p := *pin
	if p == "auto" || p == "" {
		fmt.Fprintf(os.Stderr, "ssheep: asking %s for its fingerprint...\n", *addr)
		p, err = netx.FetchPin(*addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("connector add: could not reach %s: %w\n  start it first, or pass --pin", *addr, err)
		}
	}

	// Ask it to serve this flock before writing it down: a connector that would
	// refuse us is worse than no connector at all.
	who := peer.Identity{Flock: r.ID(), NodeID: flock.NodeID(key.SignPub()), Key: key.SignKey(), Roster: f.Signed}
	conn, err := peer.Dial(*addr, p, who, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connector add: %s will not serve flock %q: %w", *addr, f.Name, err)
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
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(f.RosterPath); err != nil {
		return err
	}
	if replacing {
		fmt.Printf("updated connector %s in flock %q\n", *addr, f.Name)
	} else {
		fmt.Printf("added connector %s to flock %q — it now has %d\n", *addr, f.Name, len(r.Connectors))
	}
	publishRoster(f)
	return nil
}

func cmdConnectorRemove(args []string) error {
	fs := newFlagSet("connector remove")
	flockName := fs.String("flock", "", "which flock (required)")
	addr := fs.String("addr", "", "the connector's address (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *flockName == "" || *addr == "" {
		return errors.New("connector remove: --flock and --addr are required")
	}
	f, err := local.Resolve(*flockName)
	if err != nil {
		return err
	}
	authority, err := f.Authority()
	if err != nil {
		return err
	}
	r := f.Roster
	if !r.RemoveConnector(*addr) {
		return fmt.Errorf("connector remove: %s is not a connector for flock %q", *addr, f.Name)
	}
	r = r.Bump()
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(f.RosterPath); err != nil {
		return err
	}
	fmt.Printf("removed connector %s from flock %q — %d left\n", *addr, f.Name, len(r.Connectors))
	publishRoster(f)
	return nil
}

func cmdConnectorList(args []string) error {
	fs := newFlagSet("connector list")
	flockName := fs.String("flock", "", "which flock (default: all of them)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var flocks []*local.Flock
	if *flockName != "" {
		f, err := local.Resolve(*flockName)
		if err != nil {
			return err
		}
		flocks = []*local.Flock{f}
	} else {
		var err error
		flocks, err = local.All()
		if err != nil {
			return err
		}
	}
	for _, f := range flocks {
		fmt.Printf("flock %q\n", f.Name)
		if len(f.Roster.Connectors) == 0 {
			fmt.Printf("  no connectors yet\n\n")
			continue
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, c := range f.Roster.Connectors {
			status := "unreachable"
			if got, err := netx.FetchPin(c.Addr, 3*time.Second); err == nil {
				if got == c.Pin {
					status = "up"
				} else {
					status = "FINGERPRINT CHANGED"
				}
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\n", c.Addr, status, short(c.Pin))
		}
		_ = w.Flush()
		fmt.Println()
	}
	return nil
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
// see, run, forget, invite, flock
// ---------------------------------------------------------------------------

// flockArg pulls the flock out of the front of the arguments, so it can be a
// positional — which is what people paste.
func flockArg(fs *flag.FlagSet, args []string, banner string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args, fmt.Errorf("%s: which flock?\n\n  %s <flock> ...", banner, banner)
	}
	return args[0], args[1:], nil
}

func cmdSee(args []string) error {
	fs := newFlagSet("see")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	var flocks []*local.Flock
	if len(pos) > 0 && pos[0] != "" {
		f, err := local.Resolve(pos[0])
		if err != nil {
			return err
		}
		flocks = []*local.Flock{f}
	} else {
		if flocks, err = local.All(); err != nil {
			return err
		}
	}
	if len(flocks) == 0 {
		return errors.New("see: this machine is not in any flock yet\n\n  create one:  ssheep master flock \"myflock\"")
	}
	for _, f := range flocks {
		if err := showFlock(f, *conn); err != nil {
			fmt.Printf("flock %q — %v\n\n", f.Name, err)
		}
	}
	return nil
}

func showFlock(f *local.Flock, connectorAddr string) error {
	cl, err := master.Open(f.RosterPath, f.NodePath, connectorAddr)
	if err != nil {
		return err
	}
	defer cl.Close()
	reply, err := cl.List(10 * time.Second)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	online := 0
	for _, m := range reply.Members {
		if m.Online {
			online++
		}
	}
	fmt.Printf("flock %q  %s  (%d of %d online)\n", f.Name, f.ID, online, len(reply.Members))
	fmt.Fprintln(w, "  NAME\tROLE\tSTATUS\tID")
	for _, m := range reply.Members {
		status := "offline"
		if m.Online {
			status = "online"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", m.Name, m.Role, status, m.ID)
	}
	_ = w.Flush()
	if n := len(cl.Connectors()); n > 1 {
		fmt.Printf("  via %s (of %d connectors)\n", cl.Connector(), n)
	}
	if len(reply.Offers) > 0 {
		fmt.Printf("  %d connector(s) waiting to register — run `ssheep master %q`\n", len(reply.Offers), f.Name)
	}
	fmt.Println()
	return nil
}

func cmdRun(args []string) error {
	flockName, rest, err := flockArg(newFlagSet("run"), args, "run")
	if err != nil {
		return err
	}
	fs := newFlagSet("run")
	var names stringList
	fs.Var(&names, "name", "only this machine (repeatable; default: every sheep)")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("run: no command given\n\n  ssheep run %q -- uptime", flockName)
	}
	f, err := local.Resolve(flockName)
	if err != nil {
		return err
	}
	cl, err := master.Open(f.RosterPath, f.NodePath, *conn)
	if err != nil {
		return err
	}
	defer cl.Close()

	targets := []string(names)
	if len(targets) == 0 {
		targets = cl.SheepNames()
		if len(targets) == 0 {
			return fmt.Errorf("run: flock %q has no sheep yet", f.Name)
		}
	}
	return cl.Run(targets, argv, os.Stdout)
}

// ---------------------------------------------------------------------------
// shell
// ---------------------------------------------------------------------------

// cmdShell opens an interactive session on one machine.
//
// It is the same flock key, the same encrypted session and the same relay as a
// command. The only difference is that the conversation on top of it is ssh, so
// there is a real terminal at both ends — and still nothing listening on the
// machine you are talking to.
func cmdShell(args []string) error {
	flockName, rest, err := flockArg(newFlagSet("shell"), args, "shell")
	if err != nil {
		return err
	}
	fs := newFlagSet("shell")
	names := fs.String("name", "", "the machine to open a shell on")
	conn := fs.String("connector", "", "use this connector instead of the flock's first")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	f, err := local.Resolve(flockName)
	if err != nil {
		return err
	}
	cl, err := master.Open(f.RosterPath, f.NodePath, *conn)
	if err != nil {
		return err
	}
	defer cl.Close()

	name := *names
	if name == "" {
		// One sheep is not a choice, so it does not need making.
		sheep := cl.SheepNames()
		if len(sheep) == 1 {
			name = sheep[0]
		} else if len(sheep) == 0 {
			return fmt.Errorf("shell: flock %q has no sheep yet", f.Name)
		} else {
			return fmt.Errorf("shell: which machine? --name one of:\n\n  %s", strings.Join(sheep, "\n  "))
		}
	}

	err = cl.Shell(name, fs.Args(), os.Stdin, os.Stdout)
	var ee *master.ExitError
	if errors.As(err, &ee) {
		// A session that ended non-zero is the command's business, not a failure
		// of ssheep. Pass the status on the way ssh does, and say nothing.
		os.Exit(ee.Code)
	}
	return err
}

func cmdForget(args []string) error {
	flockName, rest, err := flockArg(newFlagSet("forget"), args, "forget")
	if err != nil {
		return err
	}
	fs := newFlagSet("forget")
	name := fs.String("name", "", "the machine to revoke (required)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("forget: --name is required")
	}
	f, err := local.Resolve(flockName)
	if err != nil {
		return err
	}
	authority, err := f.Authority()
	if err != nil {
		return err
	}
	r := f.Roster
	if !r.Remove(*name) {
		return fmt.Errorf("forget: there is no machine called %q in flock %q", *name, f.Name)
	}
	r = r.Bump()
	sr, err := flock.SignRoster(r, authority.SignKey())
	if err != nil {
		return err
	}
	if err := sr.Save(f.RosterPath); err != nil {
		return err
	}
	fmt.Printf("removed %q from flock %q (now version %d)\n", *name, f.Name, r.Version)
	publishRoster(f)
	return nil
}

func cmdInvite(args []string) error {
	flockName, rest, err := flockArg(newFlagSet("invite"), args, "invite")
	if err != nil {
		return err
	}
	fs := newFlagSet("invite")
	name := fs.String("name", "", "name for the new machine (required)")
	role := fs.String("role", flock.RoleSheep, "sheep, connector or master")
	out := fs.String("out", "", "also write the ticket to this file")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("invite: --name is required")
	}
	if !flock.ValidRole(*role) {
		return fmt.Errorf("invite: --role must be %q, %q or %q", flock.RoleSheep, flock.RoleConnector, flock.RoleMaster)
	}
	f, err := local.Resolve(flockName)
	if err != nil {
		return err
	}
	blob, err := mintInvite(f.Name, *name, *role)
	if err != nil {
		return err
	}
	if *out != "" {
		in, err := invite.Decode(blob)
		if err != nil {
			return err
		}
		if err := invite.Save(*out, in); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", *out)
	}
	fmt.Printf("\nadded %q to flock %q as a %s\n\n", *name, f.Name, *role)
	fmt.Printf("  %s\n\n", ticketLine(blob))
	if *role == flock.RoleMaster {
		fmt.Printf("a master ticket carries the flock key — the authority to add and remove\nmachines. Keep that line as safe as this machine.\n\n")
	}
	return nil
}

func cmdFlock(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("flock: the only thing here is `ssheep flock list`")
	}
	flocks, err := local.All()
	if err != nil {
		return err
	}
	if len(flocks) == 0 {
		fmt.Println("this machine is not in any flock yet")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FLOCK\tTHIS MACHINE\tMEMBERS\tCONNECTORS")
	for _, f := range flocks {
		role := f.Role
		if role == "" {
			role = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\n", f.Name, role, len(f.Roster.Members), len(f.Roster.Connectors))
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func publishRoster(f *local.Flock) {
	pushed, err := master.Publish(f.RosterPath, f.NodePath)
	switch {
	case err != nil && pushed == 0:
		fmt.Fprintf(os.Stderr, "ssheep: could not publish the roster: %v\n", err)
	case err != nil:
		fmt.Printf("published the roster to %d connector(s); one refused: %v\n", pushed, err)
	case pushed > 0:
		fmt.Printf("published the roster to %d connector(s)\n", pushed)
	}
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// roleMark is the emoji that goes with a role, so a line reads the same wherever
// it is said.
func roleMark(role string) string {
	switch role {
	case flock.RoleMaster:
		return "👑"
	case flock.RoleConnector:
		return "📡"
	default:
		return "🐑"
	}
}
