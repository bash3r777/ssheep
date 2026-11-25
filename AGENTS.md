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
internal/tunnel/    the end-to-end session: X25519 + Ed25519 + AES-GCM
internal/connector/ the relay: auth, flock registry, routing, offers, join.go
internal/sheep/     the agent: links, exec, roster following
internal/master/    the operator side: list, run, publish, offers.go
site/               the website, served at ssheep.xyz from shared hosting
deploy/             systemd units and how to run them
```

Dependencies: **none beyond the Go standard library.** Keep it that way. The
static binary with no dependencies is a feature, not an accident.

## The commands people actually use

`ssheep master flock "<name>"` is the whole setup: it creates the flock,
pre-adds the project's public relay, mints tickets, prints the lines to paste
elsewhere, accepts any connector that has registered itself, and reports.
Everything it picks is a default that a flag can override — the point is that
nobody has to read the flags. Run it again with another name for a second flock.

`ssheep sheep "<ticket>"` and `ssheep connector "<ticket>"` are the other two.
Both take the ticket as a positional argument because that is what people paste.
With no ticket they carry on doing what the machine is already enrolled as, so a
restart never changes a machine's role. A machine can be enrolled in several
flocks; each is served side by side, with its own key from `internal/local`.

Commands that act on a flock take it as the first positional (`ssheep see work`,
`ssheep run work -- uptime`), and leaving it out means "all of them".

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
