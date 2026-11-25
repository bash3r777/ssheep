# Deploying sshepard

## The connector

One machine in the flock has to be reachable. That is the connector, and it is
the only machine that needs a reachable address at all.

```sh
install -m 0755 sshepard /usr/local/bin/sshepard
install -m 0644 deploy/sshepard-connector.service /etc/systemd/system/
systemctl daemon-reload
```

It needs one file to run: the flock's roster.

```sh
# on the shepherd machine
sshepard init --name myflock

# on the connector
mkdir -p /var/lib/sshepard
scp shepherd-box:~/.sshepard/roster.json /var/lib/sshepard/
systemctl enable --now sshepard-connector
journalctl -u sshepard-connector | grep -i fingerprint
```

The connector generates its TLS certificate on first start and prints its
fingerprint. Register it from the shepherd machine — this reads the fingerprint
from the connector itself and publishes the roster, so nothing needs copying by
hand:

```sh
sshepard connector add --addr <host:port>
sshepard connector list
```

A connector adopts a roster only when it verifies and is signed by the flock key
it already trusts.

**Run more than one.** Two connectors on different networks turn a bad afternoon
into a non-event; every sheep holds a link to each of them, and a shepherd falls
through the list. `connector add` twice is the whole procedure.

Because the connector is blind, it is the least valuable machine in the flock.
If it is compromised, the attacker learns who talks to whom and nothing else. If
it is lost, nothing is lost with it: stand up another, and point the flock at
its address.

## Donating a relay

A machine with a good network position can serve strangers. Start it with
`--public` and it will take on any flock whose roster proves itself, without
being told about a single one of them in advance.

```sh
sshepard connector --public --listen :7000 \
  --max-flocks 100 --max-conns 2000 --max-members 1000
```

What that means, stated plainly:

- It sees **metadata** for every flock it serves: which machines are talking,
  when, and what they are called. It never sees a command or its output.
- It forwards ciphertext it cannot inspect, so what it carries is not its
  business — but the bandwidth and the abuse complaints are.
- Limits are yours. Per-flock quotas do not exist yet, so a total cap is all
  there is to stop one flock being the noisy one.

A relay is a good citizen by default: no connection logs, and nothing written
about who talked to whom.

The connector unit already runs as a `DynamicUser` with a state directory. For a
public relay, add `--public` and the limits to `ExecStart`.

## A sheep

```sh
install -m 0755 sshepard /usr/local/bin/sshepard
useradd --system --home /var/lib/sshepard --create-home sshepard
install -m 0644 deploy/sshepard-sheep.service /etc/systemd/system/
systemctl daemon-reload

# one time: unpack the ticket you were handed
sshepard sheep --dir /var/lib/sshepard --invite-file /root/pi.invite.json --install-only

systemctl enable --now sshepard-sheep
```

`--install-only` unpacks the ticket and exits. Without it, `sshepard sheep`
installs first if there is no identity yet, then serves — so the same line works
in a provisioning script on a fresh machine and as a no-op on one that is
already enrolled. It never overwrites an existing identity.

## Verifying

```sh
sshepard see                      # every machine, and whether it is online
sshepard run --name pi -- uptime  # one machine
sshepard run --all -- uptime      # all of them at once
```
