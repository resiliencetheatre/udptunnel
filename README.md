# udptunnel

A Linux IPv4 mesh tunnel using consumable directional XOR key material and
HMAC-SHA256 authentication. `utun-node` connects multiple hosts through one shared
TUN interface per host. Each host pair has independent keys and counters.

The intended transport is WireGuard through a VPS. The VPS routes inner encrypted
UDP packets and has **no inner tunnel keys**. It terminates outer WireGuard and
therefore has its own WireGuard keys. Inner plaintext is decrypted only by the
recipient endpoint. The VPS still sees transport peers, timing, sizes, key offsets,
and lengths, and can disrupt traffic.

See [the mesh architecture and storage graphs](future/future.md).

## Build and test

Requires Linux, a C compiler, OpenSSL development headers/libcrypto, and Python 3
for provisioning/tests. Running nodes needs `/dev/net/tun` and permission to create
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
```

## Provision a test mesh

On a trusted generator, separate from the VPS:

```sh
make test-bundles PEERS=32 KEY_BYTES=1000000 BUNDLE_DIR=mesh-test
```

`PEERS` is the **total endpoint host count**, excluding the relay. Defaults are
3 hosts and 1,000,000 bytes per directional key file. The generator supports
2–253 hosts, creates independent random material for every ordered host pair,
and copies each stream only to its sender and receiver. **Generated bundles are
for testing only, not a production key-provisioning system.**

The directory must not exist: generation refuses to overwrite keys/counters.
Failure may leave an `INCOMPLETE` directory; do not deploy it. Provision fresh
bundles in a new directory, with all relevant nodes stopped before replacing
existing state. Never reset counters for used key material.

The 32-host example produces 496 links, 992 unique streams, and 1,984 key-file
copies (1.984 GB at the example size). Each host stores 62 key files. Counters
use native binary C `long`; generator and endpoints must use the same format.

Output:

```text
mesh-test/
  README.txt
  peer-1/
    node.ini
    setup.sh
    wg0.conf.example
    keys/peer-2.out.key, peer-2.in.key, corresponding counters, ...
  peer-2/ ...
  ...
  relay/
    README.txt
    wg0.conf.example
```

Key directories/files are private (0700/0600). Copies are independent files, not
hardlinks. Only the `relay/` directory belongs on the VPS. Securely transfer each
peer bundle to its designated host; do not deliver plaintext inner keys through
an untrusted relay. The generator itself is trusted because it sees all keys.

Alternative non-overlapping address ranges can be supplied with
`TRANSPORT_NETWORK=... OVERLAY_NETWORK=...`. The Python generator also accepts
`--port` and `--mtu`; see `python3 scripts/provision_mesh.py --help`.

## WireGuard transport and startup

Defaults:

| Role | Transport address | Overlay address |
| --- | --- | --- |
| VPS | `10.0.0.1` | None |
| Host 1 | `10.0.0.2` | `10.50.0.1` |
| Host 2 | `10.0.0.3` | `10.50.0.2` |
| Host 32 | `10.0.0.33` | `10.50.0.32` |

1. Complete the WireGuard templates with separately provisioned WireGuard keys
   and the VPS public endpoint. They are templates, not runnable configurations.
   Establish transport connectivity first. Each endpoint's VPS peer must allow
   the whole transport range; the VPS maps each endpoint to its transport `/32`.
2. Enable IPv4 forwarding on the VPS and allow forwarding of UDP port 9000
   between transport hosts on `wg0`, in addition to outer WireGuard UDP 51820.
   Preserve source addresses; no SNAT is needed between these peers. Firewall
   changes are deployment-specific and are not installed by the generator.
3. Install `utun-node` on endpoints. From each host's bundle directory:

   ```sh
   utun-node -c -i node.ini    # validate without sockets or consuming keys
   sudo ./setup.sh            # create persistent otp0, local /32, peer /32 routes
   sudo utun-node -i node.ini
   ```

4. From host 1, for example, `ping 10.50.0.2` reaches host 2 through the VPS using
   end-to-end inner encryption. The recipient may initiate traffic too; there is
   no server-first pinning or client-only role.
5. Stop the node with SIGINT/SIGTERM, then run `sudo ./setup.sh down` to remove its
   persistent interface and routes. `setup.sh` refuses to modify an existing
   interface on startup; its interface name defaults to `otp0`.

Use overlay addresses for protected application traffic. Traffic sent directly
to transport addresses bypasses the inner tunnel. Keep the public VPS endpoint
reachable outside both overlay routing and any recursive tunnel route.

The generated MTU is 1280, allowing space for nested transport on common paths;
validate it against your actual path MTU. IPv4 host routes only are supported:
no IPv6, subnet routing, Ethernet bridging, or broadcast discovery.

## Node configuration

A two-host example (host 1):

```ini
[node]
interface=otp0
address=10.50.0.1
bind_address=10.0.0.2
port=9000
mtu=1280
peer_count=1

[peer1]
address=10.50.0.2
endpoint=10.0.0.3
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
