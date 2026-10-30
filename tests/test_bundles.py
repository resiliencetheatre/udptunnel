#!/usr/bin/env python3
import configparser
import hashlib
from pathlib import Path
import os
import struct
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from provision_mesh import provision
root=Path(__file__).resolve().parents[1]
node=root/'utun-node'
binary=root/(sys.argv[1] if len(sys.argv)>1 else 'tests/test_mesh')
with tempfile.TemporaryDirectory(prefix='utun-mesh-') as tmp:
    dest=provision(Path(tmp)/'bundles',3,10000,'10.1.0.0/24','10.50.0.0/24')
    hashes=set();inodes=set()
    for i in range(1,4):
        cfg=dest/f'peer-{i}'/'node.ini'
        subprocess.run([node,'-c','-i',cfg],cwd='/',check=True)
        for j in range(1,4):
            if i==j: continue
            a=dest/f'peer-{i}'/'keys'/f'peer-{j}.out.key'
            b=dest/f'peer-{j}'/'keys'/f'peer-{i}.in.key'
            assert a.read_bytes()==b.read_bytes()
            digest=hashlib.sha256(a.read_bytes()).digest()
            assert digest not in hashes;hashes.add(digest)
        for p in (dest/f'peer-{i}'/'keys').iterdir():
            st=p.stat();assert st.st_mode&0o077==0
            assert st.st_ino not in inodes;inodes.add(st.st_ino)
            if p.suffix=='.counter': assert p.read_bytes()==struct.pack('@l',0)
    assert not list((dest/'relay').glob('*.key'))
    original=(dest/'peer-1'/'node.ini').read_text()
    previous_key=(dest/'peer-1/keys/peer-2.out.key').read_bytes()
    previous_wg=(dest/'relay/wg1.netdev').read_text()
    previous_token=(dest/'relay/transport.json').read_text()
    (dest/'stale-file').write_text('remove on regeneration')
    provision(dest,3,10000,'10.1.0.0/24','10.50.0.0/24')
    assert not (dest/'stale-file').exists()
    assert (dest/'peer-1/keys/peer-2.out.key').read_bytes()!=previous_key
    assert (dest/'relay/wg1.netdev').read_text()!=previous_wg
    assert (dest/'relay/transport.json').read_text()!=previous_token
    assert (dest/'peer-1/node.ini').read_text()==original
    # A failed new generation must leave the previous complete bundle intact.
    current_key=(dest/'peer-1/keys/peer-2.out.key').read_bytes()
    try:
        provision(dest,3,10000,'10.1.0.0/24','10.50.0.0/24',mtu=1280)
        raise AssertionError('accepted OTP MTU larger than transport budget')
    except ValueError: pass
    assert (dest/'peer-1/keys/peer-2.out.key').read_bytes()==current_key
    unrelated=Path(tmp)/'unrelated';unrelated.mkdir();(unrelated/'keep').write_text('keep')
    for output in (unrelated,root):
        try:
            provision(output,3,10000,'10.1.0.0/24','10.50.0.0/24')
            raise AssertionError('accepted unsafe replacement target')
        except ValueError: pass
    assert (unrelated/'keep').read_text()=='keep'
    link=Path(tmp)/'link';link.symlink_to(dest,target_is_directory=True)
    try:
        provision(link,3,10000,'10.1.0.0/24','10.50.0.0/24')
        raise AssertionError('accepted symlink replacement target')
    except ValueError: pass
    for count,transport,overlay in [(1,'10.1.0.0/24','10.50.0.0/24'),(3,'10.1.0.0/24','10.1.0.0/24'),(3,'10.1.0.0/30','10.50.0.0/24')]:
        try:
            provision(Path(tmp)/'bad',count,10000,transport,overlay)
            raise AssertionError('accepted invalid provisioning arguments')
        except ValueError: pass
        assert not (Path(tmp)/'bad').exists()
    server_text=(dest/'relay/wg1.netdev').read_text()
    assert '10.1.0.1/24' in (dest/'relay/wg1.network').read_text()
    assert (dest/'relay/wg1.netdev').exists() and not (dest/'relay/wg0.netdev').exists()
    server_public=(dest/'relay/wireguard.pub').read_text().strip()
    assert server_text.count('[WireGuardPeer]')==3
    assert '0.0.0.0/0' not in server_text and '::/0' not in server_text
    for i in range(1,4):
        peer=dest/f'peer-{i}'
        parsed=configparser.ConfigParser();parsed.read(peer/'wg1.netdev')
        private=parsed['WireGuard']['PrivateKey']
        public=subprocess.run(['wg','pubkey'],input=private+'\n',text=True,capture_output=True,check=True).stdout.strip()
        assert public==(peer/'wireguard.pub').read_text().strip()
        assert f'PublicKey={public}\n' in server_text
        assert f'AllowedIPs=10.1.0.{i+1}/32\n' in server_text
        psk=parsed['WireGuardPeer']['PresharedKey']
        assert f'PresharedKey={psk}\n' in server_text
        assert private not in server_text
        assert parsed['WireGuardPeer']['PublicKey']==server_public
        assert parsed['WireGuardPeer']['Endpoint']=='127.0.0.1:51872'
        assert parsed['WireGuardPeer']['AllowedIPs']=='10.1.0.0/24'
        assert 'Destination=10.1.0.0/24' in (peer/'wg1.network').read_text()
        assert 'udp://127.0.0.1:51872:127.0.0.1:51872?timeout_sec=0' in (peer/'wstunnel-mesh.service').read_text()
        assert 'REPLACE_' not in ''.join(p.read_text() for p in peer.glob('*.service'))
    for script in dest.rglob('*.sh'):
        subprocess.run(['sh','-n',script],check=True)
    for secret in dest.rglob('wg1.netdev'):
        assert secret.stat().st_mode&0o077==0
    cfg=dest/'peer-1'/'node.ini'
    invalid=[original.replace('peer_count=2','peer_count=3'),
             original.replace('mtu=1128','mtu=1500'),
             original.replace('address=10.50.0.3','address=10.50.0.2'),
             original.replace('endpoint=10.1.0.4','endpoint=10.1.0.3'),
             original.replace('keys/peer-3.out.key','keys/peer-2.out.key'),
             original.replace('endpoint=10.1.0.3','endpoint=10.50.0.2'),
             original.replace('port=9000','port=-1')]
    for content in invalid:
        cfg.write_text(content)
        assert subprocess.run([node,'-c','-i',cfg],capture_output=True).returncode!=0
    cfg.write_text(original)
    # Different path, same inode must also be rejected across peer records.
    alias=cfg.parent/'keys'/'alias.key'
    os.link(cfg.parent/'keys'/'peer-2.out.key',alias)
    cfg.write_text(original.replace('keys/peer-3.out.key','keys/alias.key'))
    assert subprocess.run([node,'-c','-i',cfg],capture_output=True).returncode!=0
    cfg.write_text(original);alias.unlink()
    subprocess.run([binary,dest],check=True)
    # 32-host provisioning and validation without storing large test keys.
    large=provision(Path(tmp)/'large',32,2048,'10.1.0.0/24','10.50.0.0/24')
    assert len(list(large.glob('peer-*/keys/*.key')))==1984
    for cfg in sorted(large.glob('peer-*/node.ini')):
        subprocess.run([node,'-c','-i',cfg],check=True,stdout=subprocess.DEVNULL)
print('bundle provisioning and configuration tests passed')
