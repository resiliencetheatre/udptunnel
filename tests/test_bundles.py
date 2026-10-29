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
    dest=provision(Path(tmp)/'bundles',3,10000,'10.0.0.0/24','10.50.0.0/24')
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
    try:
        provision(dest,3,10000,'10.0.0.0/24','10.50.0.0/24')
        raise AssertionError('overwrote existing bundles')
    except ValueError: pass
    assert (dest/'peer-1'/'node.ini').read_text()==original
    for count,transport,overlay in [(1,'10.0.0.0/24','10.50.0.0/24'),(3,'10.0.0.0/24','10.0.0.0/24'),(3,'10.0.0.0/30','10.50.0.0/24')]:
        try:
            provision(Path(tmp)/'bad',count,10000,transport,overlay)
            raise AssertionError('accepted invalid provisioning arguments')
        except ValueError: pass
        assert not (Path(tmp)/'bad').exists()
    cfg=dest/'peer-1'/'node.ini'
    invalid=[original.replace('peer_count=2','peer_count=3'),
             original.replace('mtu=1280','mtu=1500'),
             original.replace('address=10.50.0.3','address=10.50.0.2'),
             original.replace('endpoint=10.0.0.4','endpoint=10.0.0.3'),
             original.replace('keys/peer-3.out.key','keys/peer-2.out.key'),
             original.replace('endpoint=10.0.0.3','endpoint=10.50.0.2'),
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
    large=provision(Path(tmp)/'large',32,2048,'10.0.0.0/24','10.50.0.0/24')
    assert len(list(large.glob('peer-*/keys/*.key')))==1984
    for cfg in sorted(large.glob('peer-*/node.ini')):
        subprocess.run([node,'-c','-i',cfg],check=True,stdout=subprocess.DEVNULL)
print('bundle provisioning and configuration tests passed')
