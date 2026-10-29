# Code audit and corrections

Date: 2026-10-29

## Scope

Reviewed the client/server packet path, key and counter handling, configuration,
network setup scripts, and build configuration. The original project compiled,
but the review found memory-safety, authentication, key-management, and default
configuration defects. The corrections below are implemented in the working tree.

## Findings and corrections

| Finding | Severity | Correction | Files |
| --- | --- | --- | --- |
| Incoming Binn packets were parsed without bounding reads by the received datagram length. A truncated packet caused a heap-buffer-overflow under AddressSanitizer. | High | Replaced the network-facing Binn format with a fixed, versioned format. Validate minimum size, magic, payload length, output capacity, and exact datagram size before processing payloads. Reject oversized datagrams. | `socket.c`, `include/utun/socket.h` |
| Partial key reads left zero-filled bytes in the key buffer, exposing the corresponding plaintext through XOR. This was reproduced with an eight-byte payload and four-byte key. | High | Require sufficient key material and complete reads before producing a packet. Failures emit no packet and do not advance the counter. | `socket.c` |
| Reading at `counter - packet_length` caused negative initial offsets and overlapping key ranges when packet sizes changed. | High | Treat the counter as the next unused byte offset. Consume payload-length bytes for XOR plus 32 separate bytes for authentication, then advance past that entire range. Validate offsets and arithmetic bounds. | `socket.c` |
| Unverified packets could select and overwrite inbound key ranges, including through replay. | High | Authenticate the header and ciphertext with HMAC-SHA256 before modifying inbound state. Reject offsets behind the inbound counter. Reject invalid traffic headers before committing key consumption. | `socket.c` |
| The server assigned the sender address to its peer address immediately before comparing them, so the check always passed. | High | Pin the server to the first successfully authenticated peer. Filter subsequent sender addresses and ports before decrypting. The client likewise filters for its configured server before decryption. | `server.c`, `client.c`, `socket.c` |
| Unchecked file-opening results could reach file I/O functions and crash the process. Startup continued despite unusable files. | Medium | Check file opens, reads, metadata, and writes. Validate required configuration, key capacity, counter format, and distinct regular files at startup. Detect file aliases by device/inode identity. Packet-time failures are rejected without dereferencing invalid file handles. | `socket.c`, `client.c`, `server.c` |
| Encryption and decryption leaked their allocated key buffers on every packet. | Medium | Use bounded stack buffers and cleanse key material before returning; also cleanse temporary decrypted payloads. | `socket.c` |
| Linux client and server scripts configured different tunnel address ranges. | Medium | Set the client to `10.0.0.2` with peer `10.0.0.1`, matching the server configuration. Align both MTUs to 1400. | `scripts/linux_client.sh` |

## Related changes

- Counter updates use a temporary file, file synchronization, atomic rename, and
  parent-directory synchronization. Reserve consumed bytes before erasing key
  material, so an erasure failure does not permit reuse. Lock the key file during
  each transaction.
- Reject packets shorter than the tunnel header before subtracting its size.
- Preserve signed TUN read results and skip failed or empty reads.
- Correct TUN packet-length log formatting.
- Validate UDP ports as decimal values from 1 through 65535.
- Remove the obsolete plaintext `auth` option and its logging. Packet
  authentication now depends on possession of matching directional key material.
- Link against OpenSSL's `libcrypto`, add transport test and sanitizer targets,
  update the socket-object header dependencies, and make installation depend on
  building the programs. Ignore and clean generated test executables.
- Update example configurations and `README.md` with protocol and provisioning
  instructions.

## Protocol and operational changes

Both endpoints must be upgraded together. Protocol v2 is incompatible with the
old unauthenticated Binn wire format.

The wire layout is:

| Field | Size |
| --- | --- |
| Magic `UTN2` | 4 bytes |
| Key offset, unsigned big-endian | 8 bytes |
| Payload length, unsigned big-endian | 2 bytes |
| XOR ciphertext | Payload length |
| HMAC-SHA256 over header and ciphertext | 32 bytes |

Each packet consumes its payload length plus 32 key bytes. Authentication uses
separate key bytes from those used for the XOR payload. Provision fresh random
keys and zero-valued counters when upgrading; never reset counters for previously
used keys or reuse material between directions.

Each endpoint requires four distinct regular files. The client's outbound key
must initially match the server's inbound key, and vice versa. Counters retain
the native binary C `long` format and must be initialized on each host. Counter
directories must permit atomic replacement. Do not modify or share these files
between running tunnel instances.

The server remains pinned to its first authenticated peer until restart. Packet
loss is supported through forward key-offset gaps; replayed and reordered packets
behind the accepted offset are dropped. Packet length and key offset remain
visible on the wire.

## Validation

The following checks passed after the corrections:

- `make`: builds both client and server.
- `make test`: exercises variable-size round trips, maximum-size payloads, every
  truncation and single-byte mutation of the tested packets, insufficient output
  capacity, replay rejection, forward offset gaps, insufficient key material,
  missing files, malformed counters, and duplicate file detection.
- The same test suite uses loopback UDP sockets to verify that an unexpected
  sender is rejected before consuming key material, and that the expected sender's
  authenticated packet is accepted.
- `make sanitize`: the transport suite passes with AddressSanitizer,
  UndefinedBehaviorSanitizer, and LeakSanitizer.
- `git diff --check`: no whitespace errors.

The loopback and final sanitizer tests ran outside the restricted sandbox because
it blocked UDP socket creation and interfered with LeakSanitizer's tracing needs.

## Limits of validation

No live TUN connection, privileged interface configuration, or end-to-end routing
was tested. Crash/power-loss recovery and file-system failure injection were not
tested. These checks are regression coverage for the implemented corrections,
not an independent cryptographic or exhaustive security audit. The bundled Binn
source remains in the repository but is no longer used to parse network packets.
