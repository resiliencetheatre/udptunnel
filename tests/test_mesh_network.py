#!/usr/bin/env python3
"""Real TUN + WireGuard relay test in disposable user/network namespaces.
Run with make test-network. No host routes, firewall, or interfaces are modified.
"""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from provision_mesh import provision

def run(args, **kwargs):
    return subprocess.run([str(a) for a in args],check=True,**kwargs)

def main(count):
    if not os.environ.get('UTUN_NET_TEST_ISOLATED'):
        env=dict(os.environ,UTUN_NET_TEST_ISOLATED=os.readlink('/proc/self/ns/net'))
        os.execvpe('unshare',['unshare','--user','--map-root-user','--net',sys.executable,__file__,'--peers',str(count)],env)
    if os.environ['UTUN_NET_TEST_ISOLATED']==os.readlink('/proc/self/ns/net'):
        raise RuntimeError('refusing to change networking without a fresh namespace')
    if not Path('/dev/net/tun').exists():
        raise RuntimeError('/dev/net/tun is required')
    processes=[]; logs=[]; capture=None; stop=threading.Event(); captured=[]
    with tempfile.TemporaryDirectory(prefix='utun-net-') as temp:
        base=Path(temp)
        bundles=provision(base/'bundles',count,100000,'10.0.0.0/24','10.50.0.0/24')
        def ns(pid,*args,**kwargs):
            return run(['nsenter','-t',pid,'-n',*args],**kwargs)
        try:
            run(['ip','link','set','lo','up'])
            Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
            run(['ip','link','add','wg0','type','wireguard'])
            def key(name):
                private=run(['wg','genkey'],capture_output=True).stdout
                public=run(['wg','pubkey'],input=private,capture_output=True).stdout.decode().strip()
                p=base/name;p.write_bytes(private);p.chmod(0o600)
                return p,public
            relay_key,relay_pub=key('relay-wg.key')
            run(['wg','set','wg0','private-key',relay_key,'listen-port','51820'])
            run(['ip','address','add','10.0.0.1/24','dev','wg0'])
            run(['ip','link','set','wg0','up'])
            peers=[]
            for i in range(1,count+1):
                proc=subprocess.Popen(['unshare','--net','sleep','600'])
                processes.append(proc)
                # Wait until unshare has installed the child's network namespace.
                deadline=time.monotonic()+5
                while os.readlink(f'/proc/{proc.pid}/ns/net')==os.readlink('/proc/self/ns/net'):
                    if time.monotonic()>deadline or proc.poll() is not None:
                        raise RuntimeError('peer namespace failed')
                    time.sleep(.01)
                pid=proc.pid;peers.append(pid)
                relay_ip=f'192.0.2.{4*(i-1)+1}'
                peer_ip=f'192.0.2.{4*(i-1)+2}'
                run(['ip','link','add',f'r{i}','type','veth','peer','name',f'p{i}'])
                run(['ip','link','set',f'p{i}','netns',pid])
                run(['ip','address','add',relay_ip+'/30','dev',f'r{i}'])
                run(['ip','link','set',f'r{i}','up'])
                ns(pid,'ip','link','set','lo','up')
                ns(pid,'ip','address','add',peer_ip+'/30','dev',f'p{i}')
                ns(pid,'ip','link','set',f'p{i}','up')
                ns(pid,'ip','link','add','wg0','type','wireguard')
                private,public=key(f'peer-{i}-wg.key')
                ns(pid,'wg','set','wg0','private-key',private,'peer',relay_pub,
                   'endpoint',relay_ip+':51820','allowed-ips','10.0.0.0/24','persistent-keepalive','1')
                run(['wg','set','wg0','peer',public,'allowed-ips',f'10.0.0.{i+1}/32'])
                ns(pid,'ip','address','add',f'10.0.0.{i+1}/32','dev','wg0')
                ns(pid,'ip','link','set','wg0','up')
                ns(pid,'ip','route','add','10.0.0.0/24','dev','wg0')
                bundle=bundles/f'peer-{i}'
                ns(pid,'sh',bundle/'setup.sh')
                log=(base/f'node-{i}.log').open('w+');logs.append(log)
                node=subprocess.Popen(['nsenter','-t',str(pid),'-n',str(ROOT/'utun-node'),'-i',str(bundle/'node.ini')],stdout=log,stderr=log)
                processes.append(node)
            # Warm up WireGuard handshakes independently of inner key consumption.
            for i,pid in enumerate(peers,1):
                ns(pid,'ping','-n','-c','1','-W','5','10.0.0.1',stdout=subprocess.DEVNULL)
            capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
            capture.bind(('wg0',0));capture.settimeout(.2)
            def reader():
                while not stop.is_set():
                    try: captured.append(capture.recv(65535))
                    except socket.timeout: pass
            thread=threading.Thread(target=reader);thread.start()
            try:
                for a,pid in enumerate(peers,1):
                    for b in range(1,count+1):
                        if a==b: continue
                        ns(pid,'ping','-n','-c','1','-W','3','-s','128','-p','0123456789abcdef0123456789abcdef',f'10.50.0.{b}',stdout=subprocess.DEVNULL)
                # Exercise an MTU-sized inner IPv4 packet with fragmentation disabled.
                ns(peers[0],'ping','-n','-c','1','-W','3','-M','do','-s','1252','10.50.0.2',stdout=subprocess.DEVNULL)
            finally:
                stop.set();thread.join()
            inner=[]
            # WireGuard is an ARPHRD_NONE device: AF_PACKET delivers the IP packet.
            for p in captured:
                if len(p)<28 or p[0]>>4!=4 or p[9]!=17: continue
                h=(p[0]&15)*4
                if int.from_bytes(p[h+2:h+4],'big')!=9000: continue
                assert p[12:14]==b'\x0a\x00' and p[16:18]==b'\x0a\x00'
                payload=p[h+8:]
                assert len(payload)>=44
                assert len(payload)==42+int.from_bytes(payload[8:10],'big')
                assert bytes.fromhex('0123456789abcdef'*2) not in payload
                inner.append(payload)
            assert inner,'relay capture saw no inner encrypted UDP packets'
            for proc in processes[1::2]:
                assert proc.poll() is None,'node exited during test'
                proc.send_signal(signal.SIGUSR1)
            print(f'PASS: {count} nodes, {count*(count-1)} directed overlay pings, MTU packet, {len(inner)} encrypted relay packets')
        except Exception:
            for log in logs:
                log.flush();log.seek(0);print(log.read(),file=sys.stderr)
            raise
        finally:
            stop.set()
            if capture: capture.close()
            for p in reversed(processes):
                if p.poll() is None:p.terminate()
            for p in processes:
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            for log in logs:log.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peers',type=int,default=3)
    args=parser.parse_args()
    if not 2<=args.peers<=32:parser.error('network test supports 2..32 hosts')
    main(args.peers)
