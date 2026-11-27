# Working on ssheep

Notes for an agent picking this repo up. Read this first, then
`docs/ARCHITECTURE.md`.

## What it is

Control machines ("sheep") from a machine you hold ("the master") through a blind
relay ("a connector"). One Go binary does all three roles.

**It is an early prototype and is not secure.** Do not present it otherwise.

## Layout

```
cmd/ssheep/         the CLI: one file per command group
internal/flock/     the roster: identity, keys, signing, node and flock ids
internal/local/     what one machine knows: the flocks it is in, and its key in each
internal/invite/    single-use tickets (a key pair plus a signed roster), and
                    the one function that unpacks one onto a machine
internal/frame/     length-prefixed messages over a stream
internal/proto/     the envelope spoken to a connector
internal/netx/      pinned TLS: self-signed certs, fingerprint dialling
internal/tunnel/    the end-to-end session: X25519 + Ed25519 + AES-GCM, and
                    conn.go, which runs a byte stream (ssh) inside it
internal/connector/ the relay: auth, flock registry, routing, offers, join.go
internal/sheep/     the agent: links, exec, roster following, and the shell it offers
internal/sshd/      the interactive shell: a real ssh server, fed by the tunnel
                    rather than by a port
internal/master/    the operator side: list, run, shell, publish, offers.go
site/               the website, served at ssheep.xyz from shared hosting
deploy/             systemd units and how to run them
```

Dependencies: **the standard library, plus three small modules the interactive
shell needs** — `golang.org/x/crypto/ssh` (a real ssh client and server),
`golang.org/x/term` (raw mode), and `github.com/creack/pty` (the pty on the far
side). That exception was made deliberately, and the alternative was worse: the
other way to get a shell is to require sshd and `authorized_keys` on every
machine, which is the setup this tool exists to avoid. All the crypto the flock
itself uses is still the standard library. Do not add a fourth.

## The commands people actually use

`ssheep master flock "<name>"` is the whole setup: it creates the flock,
pre-adds the project's public relay, mints tickets, prints the lines to paste
elsewhere, accepts any connector that has registered itself, and reports.
Everything it picks is a default that a flag can override — the point is that
nobody has to read the flags. Run it again with another name for a second flock.

`ssheep sheep "<ticket>"` and `ssheep connector "<ticket>"` are the other two, and
`ssheep join "<ticket>"` is what the printed one-liner calls: it reads the role
out of the ticket, so nobody has to name it. All take the ticket as a positional
argument because that is what people paste. With no ticket they carry on doing
what the machine is already enrolled as, so a restart never changes a machine's
role. A machine can be enrolled in several flocks; each is served side by side,
with its own key from `internal/local`.

A master ticket is the only one that carries `invite.Invite.Flock`, the flock key.
That is what makes a second master a real master — and why `--masters` defaults to
one rather than to as many as you like. `internal/master`'s `Open` refreshes the
roster from the connector before doing anything, because a master that has been
away otherwise cannot verify a machine added since.

Commands that act on a flock take it as the first positional (`ssheep see work`,
`ssheep run work -- uptime`), and leaving it out means "all of them".

`ssheep shell <flock> --name <machine>` opens a terminal on one machine. It is ssh
inside the tunnel: sshd runs in-process on the sheep, fed by the tunnel frames,
with no client auth and an ephemeral host key, because the flock already answered
who is asking. See `internal/sshd` and the "The shell" section of
`docs/ARCHITECTURE.md` — and read the three traps below before touching it.

The older step-by-step commands (`init`, `invite`, `connector add`) still exist
and still work. Keep them working: they are how somebody takes control when the
defaults do not fit.

## Build, test, check

```sh
make build     # bin/ssheep
make check     # gofmt, vet, test, build
make cross     # static binaries for linux/darwin/windows, amd64/arm64 into dist/
```

`make check` must pass before anything is pushed. There are 30-odd tests; the
worthwhile ones are in `internal/flock` (signature round trips), `internal/tunnel`
(tamper/replay/ordering) and `internal/connector` (flock isolation, replay
protection, and the roster announcement).

## Conventions

- **Comments explain why, not what.** An unexpected decision deserves the reason.
  `internal/connector/connector.go` and `internal/master/master.go` are the best
  examples to follow.
- Errors are lowercase and prefixed with the package or command name
  (`flock: ...`, `sheep: ...`).
- Roles are `sheep`, `master` and `connector`. The emoji are 👑 and 🐑.
- Do not add a dependency, a config file format, or a subcommand without a
  concrete need. The whole pitch is that it stays small.

## Two traps that cost real time

**A roster is signed over compact JSON but saved pretty-printed.** Verification
compacts the bytes again before checking. If you change how rosters are written,
`TestRosterSurvivesDisk` is the test that will catch you.

**A failing `make check`-style step that silently does not install.** A build
step once ran `make build` without `install -m 0755 bin/ssheep /usr/local/bin/`,
so the machines kept running the old binary and a fix appeared not to work.
After deploying, verify the hash, do not assume.

## Three traps in the shell

All three were bugs first, and all three looked like flakiness rather than
breakage — which is what made them expensive to find.

**Register the stream before returning to the read loop.** The sheep starts the
ssh server when the shell message arrives, and the client's ssh handshake bytes
are already in flight behind it. Registering the stream inside a goroutine means
those bytes can arrive before the stream exists, and be dropped — a shell that
works only sometimes. Registration happens synchronously in `handle`; only
`sshd.Serve` runs in the goroutine.

**Quote the arguments.** ssh carries one command string, so `argv` is quoted for
the far side's shell by `quoteForShell`. Joining with spaces silently turns
`sh -c 'seq 1 200000'` into four arguments and a cryptic error.
`internal/master/quote_test.go` pushes real arguments through a real /bin/sh.

**Say goodbye.** Nothing in the tunnel signals "this stream is finished" unless
you do it: the master sends `tunnel.KindEof`, the sheep closes the stream, which
ends the ssh connection, which hangs up the shell. Without it the sheep keeps the
session — and the shell process — alive until the connector connection happens to
drop, and the next shell from that machine is refused.

## Test environment

A relay is live at `138.201.131.115:7000` (a Proxmox VM, `10.20.20.30`, on the
`hetzner` node). Test sheep run as VMs `230` and `231` on `dellpve` and
`dellpve2` at home. Details, including how to reach them and how to tear it all
down, are in `/root/PROJECTS.md`.

## Releasing

```sh
make cross
# then upload dist/* as assets on a GitHub release (bash3r777/ssheep)
```

`site/install.sh` downloads `ssheep-<os>-<arch>` from the latest release, so the
asset names must match `make cross`.

**A release is part of shipping, not an afterthought.** The printed one-liner runs
`ssheep join`, so a release older than the `join` command makes every line the site
prints fail with `unknown command "join"` — after a cheerful "Installation
complete!". Tag first, then `make cross` (it stamps the version from
`git describe`), then attach the six binaries.

GitHub caches the `releases/latest/download/...` redirect for a few minutes after a
new release is published. Until it clears, that URL still serves the *previous*
release, even though `/releases/latest` already reports the new one as latest.
