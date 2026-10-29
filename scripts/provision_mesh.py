#!/usr/bin/env python3
"""Generate isolated test-only mesh bundles. Never replace existing state."""
import argparse
import ipaddress
import os
from pathlib import Path
import shutil
import struct


def provision(output, count, key_bytes, transport, overlay, port=9000, mtu=1280):
    if not 2 <= count <= 253:
        raise ValueError('peer count must be 2..253 (total endpoint hosts, excluding VPS)')
    if key_bytes < 1532:
        raise ValueError('key size must be at least 1532 bytes')
    if not 1 <= port <= 65535 or not 576 <= mtu <= 1498:
        raise ValueError('invalid port or MTU')
    transport = ipaddress.IPv4Network(transport)
    overlay = ipaddress.IPv4Network(overlay)
    if transport.overlaps(overlay):
        raise ValueError('transport and overlay networks must not overlap')
    if transport.num_addresses < count + 3 or overlay.num_addresses < count + 2:
        raise ValueError('networks lack usable addresses for endpoints and VPS')
    for network in (transport, overlay):
        if network.network_address.is_multicast or network.network_address.is_loopback or int(network.network_address) >> 24 == 0 or int(network.broadcast_address) >> 24 >= 224:
            raise ValueError('use unicast, non-loopback network ranges')
    output = Path(output).absolute()
    required = 2 * count * (count - 1) * key_bytes
    if not output.parent.is_dir():
        raise ValueError('output parent directory must already exist')
    if output.exists():
        raise ValueError('output already exists; use a fresh directory, never reset live keys/counters')
    if shutil.disk_usage(output.parent).free < required + 1024 * 1024:
        raise ValueError(f'insufficient free space: key copies alone require {required:,} bytes')
    print(f'TEST ONLY: {count} hosts, {count*(count-1)//2} links, {required:,} key-file bytes', flush=True)
    oldmask = os.umask(0o077)
    try:
        output.mkdir(mode=0o700)
        (output / 'INCOMPLETE').write_text('Do not use until generation completes.\n')
        for i in range(1, count+1):
            (output / f'peer-{i}' / 'keys').mkdir(parents=True, mode=0o700)
        for i in range(1, count+1):
            for j in range(1, count+1):
                if i == j:
                    continue
                tx = output / f'peer-{i}' / 'keys' / f'peer-{j}.out.key'
                rx = output / f'peer-{j}' / 'keys' / f'peer-{i}.in.key'
                with tx.open('xb') as a, rx.open('xb') as b:
                    remaining = key_bytes
                    while remaining:
                        block = os.urandom(min(remaining, 1024*1024))
                        a.write(block); b.write(block)
                        remaining -= len(block)
                for directory, peer, direction in [(i,j,'out'),(j,i,'in')]:
                    (output / f'peer-{directory}' / 'keys' / f'peer-{peer}.{direction}.counter').write_bytes(struct.pack('@l',0))
        for i in range(1,count+1):
            directory = output / f'peer-{i}'
            conf = ['[node]', 'interface=otp0', f'address={overlay[i]}',
                    f'bind_address={transport[i+1]}', f'port={port}', f'mtu={mtu}',
                    f'peer_count={count-1}', '']
            neighbours = [j for j in range(1,count+1) if j != i]
            for section,j in enumerate(neighbours,1):
                conf += [f'[peer{section}]', f'address={overlay[j]}',
                         f'endpoint={transport[j+1]}', f'port={port}',
                         f'outbound_key=keys/peer-{j}.out.key',
                         f'inbound_key=keys/peer-{j}.in.key',
                         f'outbound_counter_file=keys/peer-{j}.out.counter',
                         f'inbound_counter_file=keys/peer-{j}.in.counter', '']
            (directory/'node.ini').write_text('\n'.join(conf))
            setup = ['#!/bin/sh', 'set -eu', 'case "${1:-up}" in',
                     'up)', '# Fail rather than modify an existing interface.',
                     'ip tuntap add dev otp0 mode tun',
                     "trap 'ip link delete dev otp0' EXIT HUP INT TERM",
                     f'ip address add {overlay[i]}/32 dev otp0',
                     f'ip link set dev otp0 mtu {mtu} up']
            setup += [f'ip route add {overlay[j]}/32 dev otp0 src {overlay[i]}' for j in neighbours]
            setup += ['trap - EXIT HUP INT TERM', ';;',
                      'down) ip link delete dev otp0 ;;',
                      '*) echo "Usage: $0 [up|down]" >&2; exit 1 ;;', 'esac', '']
            (directory/'setup.sh').write_text('\n'.join(setup))
            (directory/'setup.sh').chmod(0o700)
            (directory/'wg0.conf.example').write_text(
                '[Interface]\nPrivateKey = REPLACE_WITH_THIS_HOST_WIREGUARD_PRIVATE_KEY\n'
                f'Address = {transport[i+1]}/32\n\n[Peer]\n'
                'PublicKey = REPLACE_WITH_VPS_WIREGUARD_PUBLIC_KEY\n'
                'Endpoint = REPLACE_WITH_VPS_PUBLIC_ADDRESS:51820\n'
                f'AllowedIPs = {transport}\nPersistentKeepalive = 25\n')
        relay = output/'relay'
        relay.mkdir(mode=0o700)
        wg = ['[Interface]', 'PrivateKey = REPLACE_WITH_VPS_WIREGUARD_PRIVATE_KEY',
              f'Address = {transport[1]}/{transport.prefixlen}', 'ListenPort = 51820', '']
        for i in range(1,count+1):
            wg += ['[Peer]', f'PublicKey = REPLACE_WITH_HOST_{i}_WIREGUARD_PUBLIC_KEY',
                   f'AllowedIPs = {transport[i+1]}/32', '']
        (relay/'wg0.conf.example').write_text('\n'.join(wg))
        (relay/'README.txt').write_text(
            'Relay only: no inner tunnel keys belong on this host.\n'
            'Complete the WireGuard template using separately provisioned WireGuard keys.\n'
            f'Enable IPv4 forwarding and allow UDP port {port} forwarding between endpoint\n'
            'addresses on wg0. Preserve sources (no SNAT). Allow outer WireGuard UDP 51820.\n'
            'Firewall changes depend on your existing rules; no rules are installed here.\n')
        (output/'README.txt').write_text(
            'TEST ONLY: generated random material is not a production provisioning system.\n'
            f'{count} total endpoint hosts; {key_bytes} bytes per directional key file.\n'
            'Keep this generator trusted and separate from the VPS. Copy only relay/ to VPS.\n'
            'Copy each peer directory securely to its host. Do not regenerate/reset live state.\n'
            'Complete WireGuard templates separately and establish transport connectivity.\n'
            'On each peer: utun-node -c -i node.ini; sudo ./setup.sh; sudo utun-node -i node.ini\n'
            'After stopping node: sudo ./setup.sh down\n'
            'Relative key paths resolve against node.ini, not the working directory.\n'
            'Counter files use the generator native C long format; hosts must match.\n'
            'Use SIGUSR1 for per-peer statistics. Keys are consumed and eventually exhaust.\n')
        (output/'INCOMPLETE').unlink()
    finally:
        os.umask(oldmask)
    return output


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peers',type=int,default=3,help='total endpoint hosts (2..253)')
    p.add_argument('--key-bytes',type=int,default=1000000)
    p.add_argument('--output',default='mesh-test')
    p.add_argument('--transport-network',default='10.0.0.0/24')
    p.add_argument('--overlay-network',default='10.50.0.0/24')
    p.add_argument('--port',type=int,default=9000)
    p.add_argument('--mtu',type=int,default=1280)
    args=p.parse_args()
    try:
        provision(args.output,args.peers,args.key_bytes,args.transport_network,args.overlay_network,args.port,args.mtu)
    except (ValueError,OSError) as error:
        p.exit(1,f'Provisioning failed: {error}\n')

if __name__=='__main__':
    main()
