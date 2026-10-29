# udptunnel

A UDP tunnel using directional XOR key material and HMAC-SHA256 packet authentication.
Build with `make`; a C compiler and OpenSSL development headers/libcrypto are required.
Run `make test` and `make sanitize` for transport regression tests.

## Protocol upgrade

Both endpoints must run this version. Protocol v2 rejects the old unauthenticated
Binn format. The fixed header contains `UTN2`, an eight-byte big-endian key offset,
and a two-byte payload length, followed by ciphertext and a 32-byte HMAC-SHA256.
The MAC covers the header and ciphertext. Each packet consumes its payload length
plus 32 separate key bytes for the MAC. Offsets start at zero and advance without
overlap. The old `auth` configuration option is no longer used.

Use **fresh random key material and new counters** when upgrading. Never reset a
counter for an existing key or reuse keys between directions. Each endpoint needs
four distinct regular files: `out.key`, `in.key`, `out.counter`, and `in.counter`.
The client's outbound key must initially match the server's inbound key byte for
byte, and the server's outbound key must match the client's inbound key. Provision
these copies securely before starting either process. Keep key files private.

Counter files retain the native binary C `long` format. To create a new zero-valued
counter on each host (exclusive creation avoids overwriting an existing counter):

```sh
python3 -c 'import struct; open("out.counter", "xb").write(struct.pack("@l", 0)); open("in.counter", "xb").write(struct.pack("@l", 0))'
```

The process requires read/write access to keys and counters and write access to
the counter directory for atomic replacement. Counters are flushed before key
bytes are erased; failures drop the packet. Exhausted or incomplete keys never
produce ciphertext. Do not share these files between tunnel instances or modify
them while running. Stop both endpoints before provisioning replacement material.

Incoming packets are checked for length, authentication, and replay before key
state changes. The client accepts only its configured server address; the server
pins its first authenticated peer until restart. Packet loss is supported, but
packets arriving behind the accepted key offset are dropped, including reordered
packets. This protocol does not hide packet length or key offset.

## Usage

Edit `server.ini` and `client.ini` with the file paths, server address, and UDP port.
Run from this directory so the configuration scripts can be found:

```sh
sudo ./server -i server.ini
sudo ./client -i client.ini
```

The Linux scripts configure server `10.0.0.1` and client `10.0.0.2`, both with MTU
1400. They require `iproute2` and permission to create/configure `tun0`.
Routing beyond these tunnel addresses must be configured separately.
