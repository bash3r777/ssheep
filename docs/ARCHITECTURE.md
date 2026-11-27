# How ssheep works

## The shape

```
          invite (a ticket)                join
  master ─────────────────►  sheep  ──────────────►  connector
   (no open ports)              │                          │
                                │  end-to-end encrypted    │  relays, cannot read
                                └──────────  ......  ──────┘
```

Three roles, one binary.

| Role | Job | Holds secrets | Must be reachable |
|---|---|---|---|
| **master** | Mints tickets, issues commands, holds the authority key | yes — the flock key | no |
| **connector** | Address book and relay. A member of the flock like any other, which is how it tells the flock where it is. | no | yes |
| **sheep** | Does the work | only its own key | no |

Sheep and masters only ever dial *out*. That is why no ports need to be
open anywhere except on the connector — and a connector can be any machine
that happens to be reachable, including another sheep.

## The model

**The roster is public.** It lists who is in the flock and their public keys.
It is signed by the flock key, it is small, and it is a file you can keep in
git. Every member holds a copy, so there is no database to lose and no server
to restore.

**The authority is 32 bytes.** The flock key signs rosters. It is only needed
to add or remove a machine, so it can live on a laptop that spends most of its
life switched off. Losing it does not break the flock; it just means you can
no longer change it, which is why it wants backing up.

**Private keys never move.** Each machine generates its own key pair and keeps
it. An invite is the one time a private key travels, and only because the
operator hands it over deliberately.

## Joining

1. `ssheep master flock "<name>"` (or `ssheep invite --name pi` by hand) generates
   a key pair for the new machine, adds its public key to the roster, re-signs the
   roster and prints a ticket. A master ticket additionally carries the flock key.
2. The ticket goes to the new machine, which installs two files: its own private
   key, and a copy of the roster. The printed line does both at once —
   `… | sh -s -- --ticket "<ticket>"` — so the machine is installed and joined by
   one command, run by the installer at the path it just wrote to.
3. The machine connects to a connector, which challenges it to sign a random
   nonce, and the signature is checked against the roster. The roster travels
   with the authentication message, so a connector that has never met the flock
   learns it in the same breath. No secret is ever sent to the connector.
4. From then on it is simply *in*.

The ticket is single use in the sense that it carries a key pair. `ssheep
forget --name pi` removes the entry and re-signs, which is the revocation.

## What the connector can and cannot do

It can:

- verify that a connecting machine holds the key the roster says it holds
- see who is connected, and route between them
- take on a flock it has never seen, when the flock offers a roster that proves
  itself — but only if it was started with `--public`
- tell a machine it is no longer welcome, and close its connection

It cannot:

- read a command, or the output of one
- forge a command, or impersonate a member
- add itself to the flock
- accept a roster signed by anybody other than that flock's key
- route between flocks, or tell one flock about another

Every payload the connector forwards is encrypted between master and sheep
using keys it never sees. So running a connector on somebody else's machine is
not a trust decision.

## The protocol

Two layers.

**Connector layer.** Length-prefixed JSON envelopes. `challenge`, `auth`,
`ready`, `list`, `listreply`, `route`, `data`, `roster`. The connector reads
only the envelope — who is asking and who they want to reach, plus the flock id
and the roster that proves it. The payload inside a `route` is opaque to it.

**Session layer.** Between a master and a sheep, inside those opaque payloads.
Each side generates an ephemeral X25519 key, signs it with its permanent Ed25519
key, and the signatures are checked against the roster. The transcript covers
both ephemeral keys and both identities, so neither a replayed nor a reordered
handshake can survive. The shared secret goes through HKDF-SHA256 into two
AES-256-GCM keys, one per direction, and every frame carries a counter that both
sides check. Forward secrecy comes free, because the exchange keys are per
connection.

All of it is the Go standard library. There is no third-party crypto.

## Revocation

`forget` removes the entry, bumps the roster version, and publishes the new
roster to every connector in the flock. A connector adopts a published roster
only if it verifies *and* is signed by the same flock key it already trusts, so
nobody can push a roster of their own and take the flock. Within a couple of
seconds it drops any connection whose key is no longer listed, and refuses it
next time. Sheep ask for the current roster when they connect, so they see the
change too.

This is honest about its limits: a direct conversation between two machines that
never consults the connector cannot be interrupted by a roster change. Making
revocation instant in a peer-to-peer network is a hard problem, and for now the
answer is that the connector is the chokepoint, so revoking works for as long as
the connector is in the path.

## More than one master

The flock key is the authority: it signs rosters, so whoever holds it can add and
remove machines. Keeping it in one place is the tidy answer and a fragile one — a
flock whose key lives on one laptop cannot be changed the day that laptop dies.

So a master ticket carries the flock key itself (`invite.Invite.Flock`), and the
machine that takes it is a master in the full sense: it can mint tickets, revoke
machines, accept a connector's offer and run commands. `ssheep master` mints one
spare by default, because a single copy of the key is a single point of failure for
the one thing you cannot reproduce.

A second master needs nothing special to run — a master is not a service; it
connects like any member when you type a command. But a master that has been away
holds a stale roster, and a stale roster cannot verify a machine added since, so
the handshake fails with no clue why. `master.Open` therefore asks the connector
for the roster and adopts it when it is newer, once per command, under the same
rules a sheep uses: it must verify, and be signed by the same flock key.

The cost is stated plainly: the flock key now lives in more than one place. Mint
as few master tickets as you can bear, and keep each one at least as safe as the
machine you run `ssheep` from.

## One machine, many flocks

A machine is not tied to a flock, and a flock is not tied to a machine.

- **State is per flock.** Everything a machine knows lives under
  `~/.ssheep/flocks/<name>/`: its identity there (`node.key.json`), the roster
  (`roster.json`), and the flock key if this machine holds it (`flock.key.json`).
  A machine in two flocks runs two agents side by side; losing one — being
  revoked from a flock, say — leaves the other alone.
- **One key per flock, and it comes from the ticket.** A ticket is minted before
  the machine it is meant for has ever been spoken to, so the private key has to
  be carried by the ticket. That would be a problem if a machine had one identity
  for everything: a second flock's ticket would overwrite the first. Instead the
  key belongs to the flock, so a ticket can be minted for a machine nobody has
  met, and the same box looks like a different machine to each flock it is in.
- **Roles are per flock too.** A machine can be a sheep in one flock and a
  connector in another. `ssheep flock list` prints the role this machine holds in
  each.

`ssheep master flock "<name>"` creates as many flocks as you ask for. Every
command that takes a flock takes it as the first argument (`ssheep see "work"`,
`ssheep run "work" -- uptime`); leaving it out means "all of them".

## One relay, many flocks

A connector can serve many flocks at once. That is what makes a donated relay
possible: one machine in a good network position can serve a hundred strangers
without having been told about any of them in advance.

- **A flock's id comes from its key** — `FlockID(flockKey)`. A flock therefore
  cannot claim an id it cannot sign for, and nothing has to hand ids out.
- **Peers are held per flock**, and routing only ever looks inside the sender's
  own flock. One flock cannot reach another's machines even if a node id
  collides.
- **Enrolment is self-certifying.** The signed roster rides along with the
  authentication message. The relay checks it and trusts nothing in advance:
  no signup, no account, nothing to approve.

Adopting the offered roster *before* checking the signature is deliberate. A
machine added in version 3 cannot authenticate against a relay still holding
version 1, so the relay has to accept the newer roster first. The reverse case
is what protects revocation: a relay holding version 4 refuses a revoked machine
offering the version 3 roster that still listed it.

A relay serves only the flock it was given unless it is started with `--public`.
Serving strangers is a decision worth making out loud, and the limits — how many
flocks, how many connections, how many members — belong to whoever is paying for
the bandwidth.

## How a connector gets into the roster

A connector is a member of the flock, with a key and a role, and that is what
solves the last awkward part of setting up: the master cannot know a connector's
address, because the connector is the machine with the public address and the
master has never spoken to it.

So the connector announces itself. It asks the flock what it looks like from
outside (`Ready.YouAre` — the connector's view of the connection), works out the
address it should be reachable at, and sends a signed **offer** through whatever
connector the flock already has. The master reads offers on its next command and
accepts the ones it believes.

Three checks stand between an offer and the roster:

1. **the roster lists that machine as a connector.** Only the master can add one,
   so an ordinary sheep cannot promote itself.
2. **the offer is signed by that machine.** The relay in the middle sees the offer
   in the clear, so without a signature it could rewrite the address and point the
   flock at itself.
3. **the address answers with exactly the certificate the offer claims.** The
   master dials it and checks the fingerprint before writing anything down.

If the guess is wrong — a machine behind a NAT with no port forwarding — the
master says so and nothing is added, and `--addr` is there to be told the truth.
A flock is still perfectly usable with no connector of its own: a new one starts
with the project's public relay in its roster.

## More than one connector

A single connector is a single point of failure: its bad afternoon becomes the
flock's, which is a strange thing for a design whose whole point is not needing
anyone. So a flock lists as many as it likes.

- **Every sheep connects to all of them** and holds each link open. If one goes
  down the sheep logs it, backs off, and rejoins when it comes back. Losing a
  connector costs the flock nothing.
- **A master tries them in roster order** and uses the first that answers, so
  the order *is* the preference order. A dead connector costs five seconds, not
  a broken command.
- **Sessions are per link.** A master reaching a sheep through one connector is
  a different conversation from the same master reaching it through another,
  because the two paths have nothing to do with each other.

`ssheep connector add --addr <host:port>` reads the fingerprint from the
connector itself, rewrites the roster and publishes it. `connector list` probes
each one and reports whether it answers — and whether its fingerprint has
*changed*, which is the one failure that should never pass silently.

Adding connectors makes the flock harder to take down. It does not make it
faster and it does not make it more private — it just means no single machine
can end it.

## The shell

`ssheep shell` puts a terminal on one machine. It is a real ssh session — pty,
window size, `^C`, colours, exit status — but the ssh server it talks to **runs
inside the tunnel**, not on a port. There is no sshd on the machine, nothing to
configure, and nothing to scan.

The layering is deliberate:

- **ssh carries the session, not the trust.** The tunnel has already answered who
  is asking: only a member the roster lists as a master can complete the
  handshake, and the relay sees ciphertext either way. So the ssh server is
  configured with no client authentication, and the client does not check host
  keys. Both would be a second, weaker answer to a question already answered — and
  the host key is generated per connection and thrown away, so there is nothing to
  pin and nothing to lose.
- **A pty on the far side, raw mode on this one.** The sheep allocates a real pty
  and runs the command as the user the agent runs as. The master puts your
  terminal into raw mode, asks for the window size, and forwards resizes.
- **No terminal asked for, none given.** A script piping a command through
  `ssheep shell` gets the bytes the command wrote, not a terminal's line endings
  and echo.
- **Backpressure, not buffering.** Both ends block when the reader is behind, so a
  command printing faster than the terminal can show pushes back through the
  connector instead of filling memory. A shell is never allowed to silently drop
  a byte.
- **It says goodbye.** The stream is opened and closed explicitly, so a finished
  session hangs up the shell rather than leaving it running with nobody attached.
  A session whose master was killed is replaced by the next one from that machine.

Two guards worth knowing about, because both were bugs first:

- The stream is registered *synchronously* as the shell message is handled. The
  bytes of the ssh handshake are already on their way, and a message that arrives
  before the stream exists is dropped — which showed up as a shell that worked
  only sometimes.
- Arguments are quoted for the far side's shell before being sent, because ssh
  carries one command string. Joining arguments with spaces turns `sh -c 'seq 1
  200000'` into four arguments, and the test in `internal/master/quote_test.go`
  exists to keep that honest.

`ssheep run` is unchanged: no pty, no stdin, output prefixed per machine, for
doing one thing to many machines at once.

## Deliberate omissions

- **Direct connections.** Today every byte goes through a connector. IPv6,
  UPnP and hole punching are all upgrades that sit *on top of* the relay rather
  than replacing it — the relay stays as the fallback that always works.
- **File transfer and port forwarding.** There is no `copy`, no `-L`, no
  `-R`, and no `ProxyCommand`. The session is a byte channel, so all three sit
  on top of it rather than needing a new design — but none is built.
- **The shell is Linux and macOS only.** It needs a pty, and that is the one
  place the code is platform-specific. A Windows sheep can be commanded, not
  logged into.
- **A directory of volunteer relays.** One default relay is built in, and a
  connector registers itself with its flock. What does not exist yet is a pool of
  volunteered relays, and the client-side selection that would spread flocks
  across several.
- **Per-flock quotas.** A relay can cap flocks, connections and members in
  total, but not per flock, so one member of the community could still be the
  noisy one.
- **Roster freshness between machines.** Online/offline is reported per
  connector, so with several connectors a machine connected to a different one
  shows as offline to a master asking elsewhere.
