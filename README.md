# udptunnel

A Linux IPv4 mesh tunnel using consumable directional XOR key material and
HMAC-SHA256 authentication. `utun-node` connects multiple hosts through one shared
TUN interface per host. Each host pair has independent keys and counters.

The transport is WireGuard over wstunnel WSS through a VPS. The VPS routes inner encrypted
UDP packets and has **no inner tunnel keys**. It terminates outer WireGuard and
therefore has its own WireGuard keys. Inner plaintext is decrypted only by the
recipient endpoint. The VPS still sees transport peers, timing, sizes, key offsets,
and lengths, and can disrupt traffic.

See [the mesh architecture and storage graphs](future/future.md).

## Build and test

Requires Linux, a C compiler, OpenSSL development headers/libcrypto, and Python 3
and wireguard-tools (`wg`) for provisioning/tests. Running nodes needs `/dev/net/tun` and permission to create
or attach/configure the interface (normally root/CAP_NET_ADMIN). Linux OFD locks
are used to prevent concurrent nodes consuming the same key files.

```sh
make
make test
make sanitize
```

`make` builds `utun-node` and the legacy `client`/`server` programs. `make install`
installs all three under `PREFIX/bin` (default `/usr/local/bin`).

The optional integration test creates disposable user/network namespaces with
real TUN interfaces, WireGuard connections, and a forwarding relay. It does not
change host interfaces, routes, or firewall rules. Requires `ip`, `wg`, `ping`,
`unshare`, `nsenter`, `/dev/net/tun`, kernel WireGuard support, and permission to
create user/network namespaces and use packet sockets:

```sh
make test-network                    # 3 hosts
make test-network NETWORK_PEERS=32    # all 992 directed host pairs
make test-wstunnel                    # generated WG configs + real WSS, 3 hosts
make test-wstunnel NETWORK_PEERS=32    # same WSS path with 32 hosts
```

## Provision complete test bundles

Run on a trusted generator, separate from the VPS:

```sh
make test-bundles PEERS=32 KEY_BYTES=1000000
```

This invokes the scripts in `wg-init/` and creates `mesh-test/` with ready-to-deploy
systemd-networkd WireGuard configs, wstunnel systemd services, OTP configs/keys,
and installers. There are no key or endpoint placeholders. Defaults preserve the
supplied WSS deployment: `vps.example.net:8444`, WireGuard through local UDP 51872,
server binary `/usr/local/bin/wstunnel`, and client binary `/usr/local/bin/wstunnel`.

**Every run automatically replaces the previous generated bundles without a
confirmation prompt.** All OTP keys/counters, WireGuard private keys, per-peer
WireGuard PSKs, and the shared WSS path token are regenerated. Stale peer files
are removed when reducing the count. Stop and redeploy all participating nodes
and the matching relay configuration together; old and new generations cannot
interoperate. Running the generator does not install or restart anything remotely.

Generation is staged: failure leaves the previous complete output intact. Only a
recognized generated bundle directory may be overwritten; source trees and symlink
output targets are rejected. The previous `mesh-test/` layout is recognized on
first upgrade. These checks do not ask for permission.

`PEERS` means total endpoint hosts, excluding the VPS; the default is 3, supported
range 2–253. `KEY_BYTES` defaults to 1,000,000 per directional OTP file. At 32 hosts
this means 496 links, 992 unique OTP streams, 1,984 copies (1.984 GB), and 62 key
files per host. **Bundles are test material, not a production provisioning system.**
Counters retain native binary C `long`; generator and endpoints must match.

Custom settings:

```sh
make test-bundles PEERS=4 KEY_BYTES=10000000 \
  VPS_HOST=vps.example.net WSS_PORT=8444 WG_PORT=51872 WG_IFACE=wg1 \
  WG_MTU=1200 OTP_MTU=1128 BUNDLE_DIR=mesh-test
```

| Make variable | Default | Meaning |
| --- | --- | --- |
| `VPS_HOST` | `vps.example.net` | Public IPv4 address or DNS name used by WSS clients |
| `WSS_PORT` | `8444` | Public WSS TCP port (1024–65535) |
| `WSS_BIND` | `0.0.0.0` | Server IPv4 listen address |
| `WG_PORT` | `51872` | Server WG UDP port and each client's local wstunnel port |
| `WG_MTU` | `1200` | WireGuard interface MTU, preserving the supplied scripts |
| `OTP_MTU` | `1128` | Inner MTU; must fit `OTP_MTU + 72 <= WG_MTU` |
| `SERVER_WSTUNNEL_BIN` | `/usr/local/bin/wstunnel` | Server executable path |
| `CLIENT_WSTUNNEL_BIN` | `/usr/local/bin/wstunnel` | Client executable path |
| `TRANSPORT_NETWORK` | `10.1.0.0/24` | WireGuard transport range |
| `OVERLAY_NETWORK` | `10.50.0.0/24` | OTP application range |

The 72-byte budget covers IPv4/UDP plus this tunnel's header, authentication tag,
and encrypted traffic header. Validate the underlying path MTU for your deployment.
Only transport-range routes are installed: these bundles do not route the host's
Internet default route through WireGuard. Each server peer owns exactly its `/32`;
the old scripts' overlapping `0.0.0.0/0`/`::/0` peer claims are removed.

Output:

```text
mesh-test/
  README.txt
  peer-1/                         # one complete directory per endpoint
    node.ini
    keys/                         # this host's OTP keys and counters only
    setup.sh, wait-transport.sh
    wg1.netdev, wg1.network        # actual WG keys, PSK, endpoint, and routes
    wireguard.pub
    wstunnel-mesh.service
    utun-overlay.service, utun-node.service
    install.sh, README.txt
  peer-2/ ...
  relay/                          # copy ONLY this directory to the VPS
    wg1.netdev, wg1.network        # server key + all peer public keys/PSKs
    wireguard.pub, transport.json
    wstunnel-mesh.service
    90-otp-relay.conf
    install.sh, README.txt
```

Private generated configs and keys are mode 0600 inside private directories.
Only scripts are executable. The source templates in `wg-init/` contain no private
keys or reusable WSS token. Generated test-bundle directories, key files, counters,
WireGuard `.netdev` files and `transport.json` credentials are ignored by Git.
Keep generated output in the ignored bundle directories: generated wstunnel service
files also contain the WSS path token and must not be committed.
Securely distribute each bundle to its intended host. The generator is trusted
because it sees all keys. Never put endpoint bundles or OTP keys on the VPS.

## Deploy WireGuard over wstunnel

Defaults:

| Role | Transport address | Overlay address |
| --- | --- | --- |
| VPS | `10.1.0.1` | None |
| Host 1 | `10.1.0.2` | `10.50.0.1` |
| Host 2 | `10.1.0.3` | `10.50.0.2` |
| Host 32 | `10.1.0.33` | `10.50.0.32` |

The path is:

```text
application → OTP → WireGuard → local wstunnel → WSS TCP → VPS
VPS wstunnel → WireGuard → route encrypted OTP UDP → recipient's reverse path
```

On the VPS, install `wireguard-tools`, `iproute2`, systemd-networkd, and wstunnel
at the configured path. Copy just `mesh-test/relay/`, then inside that directory:

```sh
sudo ./install.sh --start
```

On each endpoint, install the same transport dependencies and install `utun-node`
at `/usr/local/bin/utun-node` (`sudo make install` on that host). From its own
copied `peer-N/` directory:

```sh
sudo ./install.sh --start
```

`install.sh` copies configs and enables networkd/wstunnel; `--start` additionally
reloads/reconfigures wg1 and starts services, including the OTP node on endpoints.
It stops existing managed OTP services before replacing their state. Stop manually
started nodes yourself before deploying. Without `--start`, installation does not
activate the replacement transport. The installer does not download binaries.

Use systemd-networkd as the sole manager of wg1. Disable any `wg-quick@wg1` or
other manager of that interface and remove conflicting networkd configs/drop-ins.
The files use the original names `wg1.netdev` and `wg1.network`. Networkd's private
config is installed as root:systemd-network 0640 so its daemon can read the keys.

The relay installer enables IPv4 forwarding. Existing firewall policies remain
yours to manage; allow:

- Incoming **TCP 8444** (or `WSS_PORT`) for WSS.
- Loopback UDP 51872 (or `WG_PORT`) for wstunnel → WireGuard; public UDP exposure
  is unnecessary.
- Forwarding `wg1 → wg1` between transport addresses, UDP destination 9000.
  Preserve source addresses and exempt this traffic from existing SNAT rules.

Wstunnel is restricted to forwarding to `127.0.0.1:51872`; each client listens on
loopback only. WireGuard's client socket uses an ephemeral port, avoiding a
collision with the local wstunnel listener. The WSS path token matches across the
new generation. TLS retains the original self-signed behaviour, without client
certificate verification; WireGuard independently authenticates peers. See
[wstunnel's options](https://github.com/erebe/wstunnel#command-line-cmd).

Verify on an endpoint:

```sh
systemctl status wstunnel-mesh utun-overlay utun-node
sudo wg show wg1
ping 10.50.0.2             # from a different endpoint
```

Use overlay addresses for protected application traffic. Transport-address traffic
bypasses OTP. Do not run `setup.sh` manually alongside `utun-overlay.service`.
To stop an endpoint: `sudo systemctl stop utun-node utun-overlay`.

Static IPv4 host routes only are supported: no IPv6, subnet routing, Ethernet
bridging, or broadcast discovery. The VPS still requires no OTP daemon or key files.

## Node configuration

A two-host example (host 1):

```ini
[node]
interface=otp0
address=10.50.0.1
bind_address=10.1.0.2
port=9000
mtu=1128
peer_count=1

[peer1]
address=10.50.0.2
endpoint=10.1.0.3
port=9000
outbound_key=keys/peer-2.out.key
inbound_key=keys/peer-2.in.key
outbound_counter_file=keys/peer-2.out.counter
inbound_counter_file=keys/peer-2.in.counter
```

Sections run from `peer1` through `peer_count` (up to 1024 configured neighbours).
All fields are required. Addresses are static IPv4 literals, not DNS names or
prefixes. Key paths resolve relative to the INI file, independently of working
directory. Interface/address/MTU settings describe the expected network setup;
`utun-node` creates/attaches the named TUN, but does not install addresses/routes.
If editing the generated config, update `setup.sh` to match.

Outgoing packets must have the local overlay source address and a configured
peer destination. Incoming UDP endpoints select candidate key state, then HMAC
must authenticate the packet. The inner source must match that peer's overlay
address, and the inner destination must be local. This prevents peers or the VPS
from using a source-address change alone to impersonate another host. The node
never forwards decrypted traffic for other hosts.

Duplicate overlay addresses, duplicate UDP endpoints, overlapping transport and
overlay host routes, malformed counters, insufficient initial key material, and
file aliases across peers are rejected. Separate files containing duplicated
key bytes cannot be detected by these checks: provision unique material.

Send SIGUSR1 to a node for per-peer traffic/rejection counters and remaining
inbound/outbound key bytes. Statistics are also printed at shutdown. Remaining
bytes are not equivalent to application payload capacity because each packet
consumes extra authentication material. Encryption failure is logged and drops
the packet; there is no plaintext fallback or automatic key rollover.

## Wire format and key-state rules

The existing authenticated wire format is preserved: eight-byte big-endian key
offset, two-byte payload length, ciphertext, and a 32-byte HMAC-SHA256 covering
header and ciphertext. No cleartext protocol signature or peer identifier is
added. Each inner IPv4 packet of L bytes consumes L+34 key bytes (two encrypted
traffic-header bytes plus 32 separate authentication bytes).

Offsets advance without overlap. Counters are durably reserved before key bytes
are erased and before sending. Failed sends still consume reserved bytes. Packet
loss is supported, but packets behind the accepted offset—including reordered
packets—are dropped. Invalid MACs, unexpected endpoints, and replay do not advance
state. An authenticated packet that violates inner IP policy is discarded after
its inbound key range has been consumed, preventing reuse of that range.

Nodes hold exclusive OFD locks on key inodes for their lifetime; another node
cannot use those same files even via hardlink aliases. The legacy tools do not
participate in these lifetime locks. Do not share state with any other process,
modify keys/counters while running, or restore old state from snapshots. Keys and
counters must remain writable, with directory write access for atomic counter
replacement. Distinct directional files are required for every peer.

This remains a custom protocol with synchronous per-packet disk writes, finite
key material, and no independent cryptographic audit. Static endpoint mapping,
manual replenishment, and strict replay-offset handling remain intentional limits.
Discovery, authenticated endpoint roaming, rotation, and replay windows are not
implemented. A slow storage operation can stall the node's single event loop.

## Legacy point-to-point mode

`client` and `server` remain available with their original configs/scripts and
first-authenticated-peer pinning on the server. `make legacy-test-bundles` creates
`client-test/` and `server-test/` with two 10 MB test streams; unlike the new mesh
provisioner, that legacy target deletes and recreates its output directories.

The current wire format is incompatible with old Binn and `UTN2`-prefixed formats.
Use fresh keys and counters when upgrading from Binn. When upgrading from the
`UTN2` format, stop and update both ends together while preserving keys/counters.
Never reset a counter for an existing key or share material across directions.
