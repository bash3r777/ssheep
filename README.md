# ssheep

**One binary. One file. One key.**

Control a flock of machines — your own boxes, wherever they are — without opening
a port, without an account, and without trusting anybody's server. A machine can be
in as many flocks as you like.

> **Very early. Not secure.** A working prototype, published because it is useful,
> not because it is safe. There has been no audit. Do not use it for anything you
> would be upset to lose. Expect the protocol to change.

## Two things you set up, one the machines do themselves

| | | |
|---|---|---|
| 👑 | **master** | Holds a flock's key, mints tickets, runs commands. Needs no reachable address — a laptop that is usually off will do. More than one is fine, and a good idea. |
| 🐑 | **sheep** | A machine in the flock. Only ever dials *out*. Holds nothing but its own key. |
| 📡 | **relay** | A sheep that happens to be reachable. No second role to install and no machine to pick: every machine offers to relay, the ones that can be reached are used, and the ones that cannot simply stay sheep. |

The roster — a small signed file listing who is in the flock — is public and
replicated, so there is no database to lose. The only secret is the flock key,
needed only to add or remove a machine. Peers verify each other end to end: a
relay forwards ciphertext it can neither read nor forge.

## Install

```sh
curl -fsSL https://ssheep.xyz/install.sh | sh
```

Static binaries for Linux, macOS and Windows (amd64, arm64), or build it:

```sh
git clone https://github.com/bash3r777/ssheep && cd ssheep && make build
```

## Quick start

One command sets up a whole flock:

```sh
ssheep master flock "myflock"
```

It prints a line for every machine it has a ticket for — three sheep and a spare
master, by default. Paste each line on the machine it names, anything with a
shell that has never seen ssheep. The line installs the binary and joins in one
go, and the ticket says what the machine is to be, so there is no verb to get
wrong:

```sh
curl -fsSL https://ssheep.xyz/install.sh | sh -s -- --ticket "<ticket>"
```

That is the whole setup. There is no address or fingerprint to copy anywhere, and
no machine to pick: a machine that can be reached starts relaying for the flock
by itself, and one that cannot stays a perfectly good sheep. Then:

```sh
ssheep see                   # every machine, live
ssheep run "myflock" -- uptime
```

Every default is overridable — the public relay it starts with, how many tickets
are minted of each kind, the relay's port. See `ssheep master -h`.

A new flock starts with the project's public relay, so the very first machine can
be behind anything. As machines join, the ones that turn out to be reachable take
over the relaying, and the flock quietly stops depending on the project's relay.
Machines try the relays in roster order and survive losing any of them; a relay
that stops answering is dropped, so a machine that moved can take its place.

## A shell on any machine

```sh
ssheep shell "myflock" --name pi            # interactive
ssheep shell "myflock" --name pi -- htop    # one command, with a terminal
```

It is a real terminal: the window size, `^C`, `^D`, colours and exit statuses all
work, and the exit status is passed back out the way ssh does.

What makes it unusual is what it does *not* need. There is no sshd to install on
the machine, no `authorized_keys` to copy, no `known_hosts` and no first-use
trust, and nothing listening on a port — the ssh server runs *inside* the
encrypted session the flock already established, and a relay carries it
without being able to read it. The machine you are talking to is the machine the
signed roster says it is, and the flock key is what proves it.

The shell runs as the user the agent runs on that machine, so run the agent as
yourself — a systemd *user* unit is the tidy way — and a shell here is your own
environment, dotfiles and all.

## More than one master

A master ticket carries the flock key, so the machine that takes it can add and
remove machines too — and one master is not a single point of failure either. Mint
one by default (`--masters 1`) and keep it somewhere other than the master you use
every day: a flock whose key exists in exactly one place cannot be changed the day
that place dies. `--masters 0` if you would rather not have a second copy of the
key at all.

A master also catches up: it takes the current roster from a relay when it
connects, so a master that has been away still sees machines added since.

## More than one flock

A machine is not tied to a flock. Run `ssheep master` again for a second one, and
hand a machine two tickets to put it in both:

```sh
ssheep master flock "work"
ssheep flock list            # every flock this machine knows
ssheep see "work"            # one flock
ssheep see                   # all of them
```

Each flock has its own key, its own roster, its own relays and its own name for
the machine, and they live in `~/.ssheep/flocks/<name>/`. One relay can serve
several flocks at once, and a machine can be a sheep in one flock and relay for
another.

## Where to read more

- [ssheep.xyz](https://ssheep.xyz) — what it is, in one page
- [ssheep.xyz/about](https://ssheep.xyz/about) — how it works, for humans
- [ssheep.xyz/agents.txt](https://ssheep.xyz/agents.txt) — the same, for agents
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the full design, and what is deliberately missing
- [deploy/README.md](deploy/README.md) — running a relay and a sheep under systemd

## Status

Early, but working end to end: identity, invites, automatic relaying, failover
across several relays, many flocks on one relay, one machine in many flocks, the
relay path, `see`, `run`, `shell`, and revocation across networks.

Known gaps: a machine behind a NAT with no port forwarding and no IPv6 cannot
relay, and nothing opens the port for it yet — UPnP and hole punching would sit on
top of the relay rather than replace it, and neither is built. There is no file
transfer and no port forwarding, and a session is only ever per flock — `run` and
`shell` are as much as it does today.

## How it is built

Go, and — until the shell — the standard library only. The interactive shell
needs three small, well-known modules and no more: `x/crypto/ssh` for a real ssh
client and server, `x/term` for putting your terminal into raw mode, and
`creack/pty` for the pty on the far side. Everything else, including all the
crypto the flock itself uses, is the standard library. It is still one static
binary with nothing to install on the machine you are talking to.

## Licence

GPL-3.0-or-later.
