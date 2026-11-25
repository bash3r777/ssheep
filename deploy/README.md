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
fingerprint. Register that in the flock, so every machine knows where to look
and which certificate to trust:

```sh
# on the shepherd machine
sshepard invite --name <machine> --connector <host:port> --pin <fingerprint>
```

That rewrites the roster, so copy it to the connector again. The connector
notices the file change on its own and hot-reloads — no restart needed.

Because the connector is blind, it is the least valuable machine in the flock.
If it is compromised, the attacker learns who talks to whom and nothing else. If
it is lost, nothing is lost with it: stand up another, and point the flock at
its address.

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
