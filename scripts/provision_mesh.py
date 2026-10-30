#!/usr/bin/env python3
"""Recreate test mesh bundles with WireGuard over wstunnel deployment files."""
import argparse
import ipaddress
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import fcntl
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
WG_INIT = ROOT / "wg-init"
sys.path.insert(0, str(WG_INIT))
from generate import validate as validate_transport


def _provision(output, count, key_bytes, transport, overlay, port=9000, mtu=1128):
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
        (output/'relay').mkdir(mode=0o700)
        (output/'README.txt').write_text(
            'TEST ONLY: generated random material is not a production provisioning system.\n'
            f'{count} total endpoint hosts; {key_bytes} bytes per directional key file.\n'
            'Keep this generator trusted and separate from the VPS. Copy only relay/ to VPS.\n'
            'Each regeneration replaces ALL keys. Stop and redeploy all participating hosts.\n'
            'WireGuard and wstunnel configs/services are generated and ready to install.\n'
            'On each peer: utun-node -c -i node.ini; sudo ./setup.sh; sudo utun-node -i node.ini\n'
            'After stopping node: sudo ./setup.sh down\n'
            'Relative key paths resolve against node.ini, not the working directory.\n'
            'Counter files use the generator native C long format; hosts must match.\n'
            'Use SIGUSR1 for per-peer statistics. Keys are consumed and eventually exhaust.\n')
        (output/'INCOMPLETE').unlink()
    finally:
        os.umask(oldmask)
    return output


def deploy_files(output, count, transport, host, ws_port, wg_port, wg_mtu,
                 server_bind, server_binary, client_binary, port, wg_interface):
    transport = ipaddress.IPv4Network(transport)
    relay = output/'relay'
    subprocess.run(['sh', str(WG_INIT/'create-server.sh'), '--output', str(relay),
                    '--address', f'{transport[1]}/{transport.prefixlen}',
                    '--interface', wg_interface, '--port', str(wg_port), '--mtu', str(wg_mtu), '--host', host,
                    '--ws-port', str(ws_port), '--bind', server_bind,
                    '--binary', server_binary], check=True)
    template = (WG_INIT/'install-transport.sh').read_text()
    write = lambda p, data, mode=0o600: (p.write_text(data), p.chmod(mode))
    for i in range(1,count+1):
        peer = output/f'peer-{i}'
        subprocess.run(['sh', str(WG_INIT/'create-client.sh'), str(transport[i+1]),
                        '--output', str(peer), '--server-dir', str(relay),
                        '--binary', client_binary], check=True)
        for name in ('utun-node.service', 'utun-overlay.service'):
            write(peer/name, (WG_INIT/name).read_text())
        write(peer/'wait-transport.sh', '#!/bin/sh\nset -eu\nn=0\n'
              f'until ip -4 -o address show dev {wg_interface} | grep -F " {transport[i+1]}/" >/dev/null; do\n'
              '    n=$((n+1)); [ "$n" -lt 30 ] || exit 1; sleep 1\ndone\n', 0o700)
        extra = """[ -x /usr/local/bin/utun-node ] || { echo 'Install utun-node first.' >&2; exit 1; }
# Stop the old node before replacing any key/counter files.
for unit in utun-node.service utun-overlay.service; do
    if [ "$(systemctl show --property=LoadState --value "$unit")" != not-found ]; then
        systemctl stop "$unit"
    fi
done
install -d -m 0700 /etc/utun /etc/utun/keys
install -m 0600 node.ini /etc/utun/node.ini
for file in keys/*; do install -m 0600 "$file" "/etc/utun/keys/${file##*/}"; done
install -d -m 0755 /usr/local/libexec
install -m 0700 setup.sh /usr/local/libexec/utun-setup
install -m 0700 wait-transport.sh /usr/local/libexec/utun-wait-transport
install -m 0644 utun-node.service utun-overlay.service /etc/systemd/system/
"""
        script = template.replace('@BINARY@', client_binary).replace('@EXTRA_INSTALL@', extra).replace('@IFACE@',wg_interface)
        script = script.replace('@EXTRA_START@', '    systemctl enable --now utun-node.service')
        write(peer/'install.sh', script, 0o700)
        write(peer/'README.txt', f"""Host {i}: transport {transport[i+1]}, local WireGuard endpoint 127.0.0.1:{wg_port}.
Install wireguard-tools, iproute2, systemd-networkd, utun-node (/usr/local/bin),
and wstunnel ({client_binary}). Then: sudo ./install.sh --start
The installer copies config/state and enables networkd/wstunnel. --start also
activates them and enables the OTP node. Existing node services are stopped
before replacing keys; regenerate/redeploy the whole mesh together.
Do not run setup.sh manually when using utun-overlay.service.
Use networkd for {wg_interface}; disable any wg-quick@{wg_interface} or other manager for this interface.
Existing networkd {wg_interface} configs/drop-ins must not conflict with these files.
WSS endpoint: wss://{host}:{ws_port}; no default route is installed via WireGuard.
Transport configs contain private keys. Never share this directory with another peer.
Generated wstunnel retains the original self-signed TLS behaviour (certificate
verification off); WireGuard authenticates the transport peers.
""")
    extra = 'install -m 0644 90-otp-relay.conf /etc/sysctl.d/90-otp-relay.conf\n'
    script = template.replace('@BINARY@', server_binary).replace('@EXTRA_INSTALL@', extra).replace('@IFACE@',wg_interface)
    script = script.replace('@EXTRA_START@', "    printf '1\\n' > /proc/sys/net/ipv4/ip_forward")
    write(relay/'install.sh', script, 0o700)
    write(relay/'README.txt', f"""VPS relay: WireGuard {transport[1]}, UDP {wg_port}; WSS TCP {ws_port}.
No OTP keys or node daemon belong here. Copy ONLY this relay directory to the VPS.
Install wireguard-tools, iproute2, systemd-networkd, and wstunnel at {server_binary}.
Run sudo ./install.sh --start to install and activate the generated configuration.
Use networkd for {wg_interface}; disable wg-quick@{wg_interface}/other managers for this interface and
remove conflicting {wg_interface} networkd configs/drop-ins before activation.
Permit incoming TCP {ws_port}. Wstunnel forwards only to 127.0.0.1:{wg_port}.
Allow local-loopback UDP {wg_port}; public UDP {wg_port} is unnecessary.
Allow FORWARD {wg_interface} -> {wg_interface}, source/destination {transport}, UDP destination {port}.
Preserve source addresses; exempt this internal traffic from any existing SNAT.
Firewall rules are not installed because existing policies vary.
All server peers have distinct /32 AllowedIPs; no 0.0.0.0/0 peer claims.
Every regeneration changes the WireGuard keys, per-peer PSKs and WSS path token.
Deploy the matching peer bundles together; old peer configs will stop working.
""")
    # No private client key ever gets copied into relay/. Server only holds its
    # own private key and the shared WireGuard PSKs needed to terminate WG.


def provision(output, count, key_bytes, transport, overlay, port=9000, mtu=1128,
              *, host='vps.example.net', ws_port=8444, wg_port=51872, wg_mtu=1200, wg_interface='wg1',
              server_bind='0.0.0.0', server_binary='/usr/local/bin/wstunnel',
              client_binary='/usr/local/bin/wstunnel'):
    validate_transport(host,wg_port,ws_port,wg_mtu,server_binary)
    validate_transport(host,wg_port,ws_port,wg_mtu,client_binary)
    ipaddress.IPv4Address(server_bind)
    if mtu+72 > wg_mtu:
        raise ValueError('OTP MTU + 72 bytes must fit inside WireGuard MTU')
    target = Path(output).absolute()
    # Regeneration is automatic for generated bundles, never for source trees,
    # home directories, filesystem roots, or a symlink pointing elsewhere.
    if target.is_symlink() or target.resolve() in (ROOT, Path.home(), Path('/')) or target.resolve() in ROOT.parents:
        raise ValueError('unsafe output directory')
    if not target.parent.is_dir():
        raise ValueError('output parent must exist')
    def generated():
        if not target.exists(): return True
        if not target.is_dir(): return False
        marker=target/'.utun-test-bundle'
        if marker.is_file() and marker.read_text()=='utun-test-bundle-v1\n': return True
        # Recognize the original mesh-test layout for seamless first upgrade.
        readme=target/'README.txt'
        return (readme.is_file() and readme.read_text().startswith('TEST ONLY: generated random material')
                and (target/'relay').is_dir() and any(target.glob('peer-*/node.ini')))
    with (target.parent/('.'+target.name+'.lock')).open('a') as lock:
        os.chmod(lock.name,0o600)
        fcntl.flock(lock,fcntl.LOCK_EX)
        if not generated(): raise ValueError('existing output is not a generated mesh bundle')
        with tempfile.TemporaryDirectory(prefix='.'+target.name+'-build-',dir=target.parent) as temp:
            stage=Path(temp)/'bundle'
            _provision(stage,count,key_bytes,transport,overlay,port,mtu)
            deploy_files(stage,count,transport,host,ws_port,wg_port,wg_mtu,
                         server_bind,server_binary,client_binary,port,wg_interface)
            (stage/'.utun-test-bundle').write_text('utun-test-bundle-v1\n')
            # Keep the previous complete generation if any generation step fails.
            old=Path(temp)/'previous'
            if target.exists(): target.rename(old)
            try: stage.rename(target)
            except OSError:
                if old.exists(): old.rename(target)
                raise
        return target


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peers',type=int,default=3,help='total endpoint hosts (2..253)')
    p.add_argument('--key-bytes',type=int,default=1000000)
    p.add_argument('--output',default='mesh-test')
    p.add_argument('--transport-network',default='10.1.0.0/24')
    p.add_argument('--overlay-network',default='10.50.0.0/24')
    p.add_argument('--port',type=int,default=9000)
    p.add_argument('--mtu',type=int,default=1128)
    p.add_argument('--vps-host',default='vps.example.net')
    p.add_argument('--wss-port',type=int,default=8444)
    p.add_argument('--wg-port',type=int,default=51872)
    p.add_argument('--wg-mtu',type=int,default=1200)
    p.add_argument('--wg-interface',default='wg1')
    p.add_argument('--wss-bind',default='0.0.0.0')
    p.add_argument('--server-wstunnel-bin',default='/usr/local/bin/wstunnel')
    p.add_argument('--client-wstunnel-bin',default='/usr/local/bin/wstunnel')
    args=p.parse_args()
    try:
        provision(args.output,args.peers,args.key_bytes,args.transport_network,args.overlay_network,args.port,args.mtu,
                  host=args.vps_host,ws_port=args.wss_port,wg_port=args.wg_port,wg_mtu=args.wg_mtu,
                  server_bind=args.wss_bind,wg_interface=args.wg_interface,server_binary=args.server_wstunnel_bin,
                  client_binary=args.client_wstunnel_bin)
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        p.exit(1,f'Provisioning failed: {error}\n')

if __name__=='__main__':
    main()
