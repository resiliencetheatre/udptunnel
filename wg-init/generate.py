#!/usr/bin/env python3
"""WireGuard over wstunnel configuration generation, shared by wg-init scripts."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

HERE = Path(__file__).resolve().parent


def write(path, content, mode=0o600):
    path.write_text(content)
    path.chmod(mode)


def wg(command, data=None):
    return subprocess.run(['wg', command], input=data, text=True, capture_output=True,
                          check=True).stdout.strip()


def validate(host, wg_port, ws_port, mtu, binary):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host):
        raise ValueError('public host must be an IPv4 address or DNS hostname')
    if not 1024 <= ws_port <= 65535 or not 1 <= wg_port <= 65535:
        raise ValueError('WSS port must be 1024..65535; WireGuard port must be 1..65535')
    if not 648 <= mtu <= 9000:
        raise ValueError('WireGuard MTU must be 648..9000')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', binary):
        raise ValueError('wstunnel binary must be an absolute path without spaces')


def unit(kind, **values):
    text = (HERE/f'{kind}-systemd'/'wstunnel-mesh.service').read_text()
    for key, value in values.items():
        text = text.replace('@'+key+'@', str(value))
    if re.search(r'@[A-Z_]+@', text):
        raise ValueError('unresolved service template field')
    return text


def network(address, mtu, interface, transport=None, relay=False):
    text = f'[Match]\nName={interface}\n\n[Link]\nMTUBytes={mtu}\nRequiredForOnline=no\n\n[Network]\nAddress={address}\n'
    if relay:
        text += 'IPForward=ipv4\n'
    if transport:
        text += f'\n[Route]\nDestination={transport}\nScope=link\n'
    return text


def server(directory, address='10.1.0.1/24', port=51872, mtu=1200,
           host='vps.example.net', ws_port=8444, bind='0.0.0.0', binary='/usr/local/bin/wstunnel', interface='wg1'):
    validate(host, port, ws_port, mtu, binary)
    ipaddress.IPv4Address(bind)
    if not re.fullmatch(r'wg[0-9]+', interface): raise ValueError('WireGuard interface must be wg followed by a number')
    iface = ipaddress.IPv4Interface(address)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private = wg('genkey'); public = wg('pubkey', private+'\n')
    prefix = secrets.token_urlsafe(48)
    write(directory/'wireguard.pub', public+'\n')
    write(directory/f'{interface}.netdev', f'[NetDev]\nName={interface}\nKind=wireguard\n\n'
          f'[WireGuard]\nListenPort={port}\nPrivateKey={private}\n')
    write(directory/f'{interface}.network', network(address, mtu, interface, relay=True))
    write(directory/'wstunnel-mesh.service', unit('server', BINARY=binary, PREFIX=prefix,
          WG_PORT=port, BIND=bind, WS_PORT=ws_port, IFACE=interface))
    write(directory/'90-otp-relay.conf', 'net.ipv4.ip_forward=1\n')
    write(directory/'transport.json', json.dumps(dict(host=host, port=port, mtu=mtu,
          ws_port=ws_port, prefix=prefix, network=str(iface.network),
          address=str(iface.ip), interface=interface), indent=2)+'\n')


def client(address, directory, server_dir, binary='/usr/local/bin/wstunnel'):
    server_dir = Path(server_dir)
    meta = json.loads((server_dir/'transport.json').read_text())
    validate(meta['host'], meta['port'], meta['ws_port'], meta['mtu'], binary)
    ip = ipaddress.IPv4Address(address)
    net = ipaddress.IPv4Network(meta['network'])
    if ip not in net or str(ip)==meta['address'] or ip in (net.network_address,net.broadcast_address):
        raise ValueError('client address must be a usable transport host distinct from relay')
    iface = meta['interface']
    text = (server_dir/f'{iface}.netdev').read_text()
    if f'AllowedIPs={ip}/32\n' in text:
        raise ValueError('client address already present in server configuration')
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private = wg('genkey'); public = wg('pubkey', private+'\n'); psk = wg('genpsk')
    server_public = (server_dir/'wireguard.pub').read_text().strip()
    write(directory/'wireguard.pub', public+'\n')
    # ListenPort is deliberately ephemeral; local wstunnel owns the configured UDP port.
    write(directory/f'{iface}.netdev', f'[NetDev]\nName={iface}\nKind=wireguard\n\n'
          f'[WireGuard]\nPrivateKey={private}\n\n[WireGuardPeer]\nPublicKey={server_public}\n'
          f'PresharedKey={psk}\nAllowedIPs={net}\nEndpoint=127.0.0.1:{meta["port"]}\nPersistentKeepalive=25\n')
    write(directory/f'{iface}.network', network(f'{ip}/32', meta['mtu'], iface, str(net)))
    write(directory/'wstunnel-mesh.service', unit('client', BINARY=binary, PREFIX=meta['prefix'],
          WG_PORT=meta['port'], HOST=meta['host'], WS_PORT=meta['ws_port'], IFACE=iface))
    write(server_dir/f'{iface}.netdev', text+f'\n[WireGuardPeer]\nPublicKey={public}\n'
          f'PresharedKey={psk}\nAllowedIPs={ip}/32\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('server')
    s.add_argument('--output', default='server')
    s.add_argument('--address', default='10.1.0.1/24')
    s.add_argument('--interface', default='wg1')
    s.add_argument('--port', type=int, default=51872)
    s.add_argument('--mtu', type=int, default=1200)
    s.add_argument('--host', default='vps.example.net')
    s.add_argument('--ws-port', type=int, default=8444)
    s.add_argument('--bind', default='0.0.0.0')
    s.add_argument('--binary', default='/usr/local/bin/wstunnel')
    c = sub.add_parser('client')
    c.add_argument('address')
    c.add_argument('--output')
    c.add_argument('--server-dir', default='server')
    c.add_argument('--binary', default='/usr/local/bin/wstunnel')
    a = p.parse_args()
    os.umask(0o077)
    try:
        if a.command=='server':
            server(a.output, a.address, a.port, a.mtu, a.host, a.ws_port, a.bind, a.binary, a.interface)
        else:
            client(a.address, a.output or a.address, a.server_dir, a.binary)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        # Never print CalledProcessError stdout: wg output may contain key material.
        p.exit(1, f'WireGuard generation failed: {error}\n')


if __name__=='__main__':
    main()
