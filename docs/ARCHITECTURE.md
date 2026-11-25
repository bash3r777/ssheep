# How sshepard works

## The shape

```
          invite (a ticket)                join
  shepherd ─────────────────►  sheep  ──────────────►  connector
   (no open ports)              │                          │
                                │  end-to-end encrypted    │  relays, cannot read
                                └──────────  ......  ──────┘
```

Three roles, one binary.

| Role | Job | Holds secrets | Must be reachable |
|---|---|---|---|
| **shepherd** | Mints invites, issues commands, holds the authority key | yes — the flock key | no |
| **connector** | Address book and relay | no | yes |
| **sheep** | Does the work | only its own key | no |

Sheep and shepherds only ever dial *out*. That is why no ports need to be
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

1. `sshepard invite --name pi` generates a key pair for the new machine, adds
   its public key to the roster, re-signs the roster and prints a ticket.
2. The ticket goes to the new machine, which installs two files: its own private
   key, and a copy of the roster.
3. The machine connects to the connector, which challenges it to sign a random
   nonce. The connector checks that signature against the roster. No secret is
   ever sent to the connector.
4. From then on it is simply *in*.

The ticket is single use in the sense that it carries a key pair. `sshepard
forget --name pi` removes the entry and re-signs, which is the revocation.

## What the connector can and cannot do

It can:

- verify that a connecting machine holds the key the roster says it holds
- see who is connected, and route between them
- adopt a roster published by a shepherd, after checking the signature and that
  it belongs to the same flock
- tell a machine it is no longer welcome, and close its connection

It cannot:

- read a command, or the output of one
- forge a command, or impersonate a member
- add itself to the flock
- accept a roster signed by anybody other than this flock's key

Every payload the connector forwards is encrypted between shepherd and sheep
using keys it never sees. So running a connector on somebody else's machine is
not a trust decision.

## The protocol

Two layers.

**Connector layer.** Length-prefixed JSON envelopes. `challenge`, `auth`,
`ready`, `list`, `listreply`, `route`, `data`, `roster`. The connector reads
only the envelope — who is asking and who they want to reach. The payload
inside a `route` is opaque to it.

**Session layer.** Between a shepherd and a sheep, inside those opaque payloads.
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

## Deliberate omissions

- **Direct connections.** Today every byte goes through the connector. IPv6,
  UPnP and hole punching are all upgrades that sit *on top of* the relay rather
  than replacing it — the relay stays as the fallback that always works.
- **Interactive shells.** `run` executes and streams output; there is no pty and
  no stdin yet.
- **File transfer.** `copy` is not implemented.
- **A connector that boots with nothing.** A connector needs a roster before it
  can authenticate anyone, so the very first one is handed a roster by hand.
  After that the flock keeps it up to date on its own.
