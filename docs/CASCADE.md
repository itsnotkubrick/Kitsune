# Cascade v2

Cascade adds entry nodes in front of one Kitsune server. The entry node forwards
IPv4 TCP/UDP; the client protocol terminates on the main server. No user passwords,
subscription tokens, REALITY private keys or certificate private keys are copied
to the entry node.

## Supported deployment

Use a **dedicated Linux entry VPS**, with systemd, bash, nftables, iproute2,
util-linux and Python 3. On Ubuntu 22.04/24.04 prerequisites are:

```sh
apt-get update
apt-get install -y nftables iproute2 util-linux python3
```

The installer does not download dependencies or change firewall backends. It
refuses unowned installation files, unowned `ip kitsune_bridge` tables and foreign
FORWARD chains. A first installation also refuses a host that already has IPv4
forwarding enabled. This intentionally excludes unreviewed coexistence with
Docker/UFW/router workloads. Input/output firewall tables are preserved; a provider
firewall must separately allow the selected entry ports. Existing SSH and other
local listeners are checked before applying rules. Keep provider console access.

The generated configuration contains one owned table, `ip kitsune_bridge`:

- DNAT matches the entry interface, local IPv4, protocol and selected port.
- SNAT and forwarding additionally match the original conntrack destination and
  port, the correct direction and the main server address. Related ICMP errors
  for these connections are allowed for path-MTU/error handling.
- The forward chain drops unrelated transit on this dedicated node. It does not
  change global iptables policies or input/output access rules.
- Updates replace **only this table**, in one nftables transaction after
  `nft --check`. There is no `flush ruleset`.

The local IPv4 and interface are determined from the route to the main server at
startup. Multi-interface and provider NAT installations need a separate network
design; the node host in subscriptions must actually reach that local address.
IPv6 forwarding/NAT is not implemented. Use an IPv4 address or an A-only hostname
for the entry node; do not advertise an AAAA record as a working cascade endpoint.
This does not change client IPv6 or DNS routing and does not prove absence of DNS
leaks. If another service later adds forwarding rules, startup will stop with a
conflict rather than silently take ownership.

## Connections and subscriptions

Supported: VLESS + REALITY, VLESS + XHTTP + REALITY, VLESS + WebSocket + TLS,
Trojan + gRPC + TLS, VMess + WebSocket + TLS, Shadowsocks 2022 (TCP and UDP),
Hysteria 2 and TUIC. Ports come from the enabled connections; they are not always
443. Connections using single443 use the shared port. A mismatched ExternalPort
is rejected in the cascade API until explicit entry/backend port mappings exist.

Profiles keep user credentials, TLS names, transport settings and certificate
pins. Only entry address/name and optional selected REALITY SNI change. Direct
profiles remain available. Access groups are checked before expansion. A node's
REALITY SNI is added only to the selected REALITY connections. Saving an SNI
configuration stages subscriptions; an apply failure restores previous node
settings and attempts to restore cores, returning an error rather than success.
An unsuccessful rollback requires operator attention; do not treat the response
as proof that the live cores match the database.

`selection_mode` is additive:

- missing: legacy `only=[]` means all; a nonempty list selects those tags;
- `all`: all relayable connections, including future ones;
- `selected`: a nonempty explicit tag list;
- `none`: no connections.

Disabling/deleting a node in the panel affects subscriptions, **not the remote
machine**. Run removal on that machine to remove forwarding. Changing a
subscription does not instantly update existing apps or open connections.

## Install, update, stop and remove

Generate the script for a node in the panel, review it, and paste the entire
block into the node's root shell. The block runs the installer from a protected
temporary file and removes that file on exit. Bash and the listed prerequisites
must be available on the node.

Re-run a newly generated script to change ports or main-server IP. It applies
synchronously even if the oneshot systemd service is already active. Operations
are serialized by locks. Files are installed with restrictive permissions.

`kitsune-bridge.service` starts after network-online. On each start it computes the
current local interface/address and reapplies its table. A reboot retains files
but not an assumed live process. `systemctl stop kitsune-bridge` removes the owned
table while keeping installation files. `systemctl start kitsune-bridge` restores
it. Restart/stop interrupts service; do not use restart as a zero-downtime update.

To remove the bridge:

```sh
bash /usr/local/sbin/kitsune-bridge-apply remove
```

The installer checks ownership and deletes only its table, helper and unit.
Failures are returned as failures; recovery files are retained. On a dedicated node where it originally enabled forwarding and no foreign FORWARD
chains have appeared, it disables forwarding before removing its guard table, so
the host does not become an unrestricted router. When foreign forwarding chains
have appeared, shared `net.ipv4.ip_forward` is left unchanged and must be reviewed
by the operator. On a failed apply, its original forwarding value is restored
when it had been disabled before that operation. Do not make concurrent network
changes through another administrator/tool during an install or rollback.

## Recovery

Before changing an existing bridge, keep a copy of the generated script and an
independent console connection. The installer keeps its last table snapshot and
helper in `/var/lib/kitsune-bridge/previous.nft` and `previous-apply`. An apply or
systemd activation failure attempts to restore the previous owned table and files.
A failed operation prints the root-only recovery directory; it never prints keys
or packet contents. Rollback failure is explicitly reported and requires console
access. These files may reveal infrastructure addresses and should remain private.

For a completed update that you want to revert, copy the saved helper to a separate
file before executing it (the installer refreshes its previous-version files):

```sh
cp /var/lib/kitsune-bridge/previous-apply /root/bridge-rollback.sh
chmod 700 /root/bridge-rollback.sh
bash /root/bridge-rollback.sh
```

Review its destination/ports first and restore the corresponding node selection in
the panel. Do not globally restore firewall tables over unrelated changes. Existing
conntrack flows may keep the old translation until they end; the installer does
not flush connection tracking. A new policy may intentionally block removed ports.

## Diagnostics

TCP connect is labeled **TCP reachability**, not VPN or end-to-end success. The API
returns per-port outcomes, probe kind, timestamps and bounded errors (timeout,
refused, unreachable, cancelled). A manual check is limited to two concurrent
requests and a 20-second context, including DNS. Resolved probe addresses are
validated and dialed numerically, without a second DNS lookup.

The monitor stores per-port results and configuration fingerprints. Three TCP
failures hide the affected TCP profile when auto-hide is enabled; two successful
checks recover it. UDP-only and dual-transport profiles are not hidden on TCP-only
evidence. Stale observations older than five minutes and changed node settings
must not hide a profile. States are in memory and return to unknown after a panel
restart; history and authenticated protocol probes are future work.

Measurements originate on the **main server** and do not establish reachability
from a client's network. NAT makes clients appear to the main server as the entry
node; IP-based device accounting/limits therefore need care. HWID is a separate
client-supplied mechanism.

## Validation and release gate

Unit and fault-injection tests:

```sh
go test ./...
go vet ./...
node --test tools/test/*.test.js
```

The installer lifecycle suite executes the real generated shell with isolated
command doubles. It tests installation, update, changed IP/port, repeated apply,
conflicts, failure/rollback and removal. It does not boot real systemd.

A real Linux nftables TCP/UDP test is opt-in:

```sh
KITSUNE_BRIDGE_NETNS=1 go test ./internal/bridge \
  -run '^TestInstallerNetworkNamespaces$' -v
```

It requires nft, iproute2, Python 3, util-linux and permission to create user/network
namespaces and veth devices. All links, sysctls and firewall rules are confined to
temporary namespaces. It validates DNAT/SNAT, real packet exchange, updates,
stop/start, restoration after lost rules, unrelated-transit denial, removal and
preservation of an unrelated table. systemd is a command double; restoration is a
reboot-state simulation, not an actual machine reboot.

Before deployment/release, additionally test Ubuntu 22.04 and 24.04, a real boot,
REALITY and Hysteria 2/TUIC clients through the bridge, authentication failure,
expected exit IP, DNS/IPv6 behavior, client-network reachability, entry/main-server
failure and recovery. Passing the namespace test is not a claim of protocol E2E
compatibility, DPI invisibility or production readiness.
