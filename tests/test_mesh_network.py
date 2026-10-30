#!/usr/bin/env python3
"""Real TUN + WireGuard relay test in disposable user/network namespaces.
Run with make test-network. No host routes, firewall, or interfaces are modified.
"""
import argparse
import os
from pathlib import Path
import signal
import shlex
import shutil
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

def main(count, wstunnel=False):
    if not os.environ.get('UTUN_NET_TEST_ISOLATED'):
        env=dict(os.environ,UTUN_NET_TEST_ISOLATED=os.readlink('/proc/self/ns/net'))
        os.execvpe('unshare',['unshare','--user','--map-root-user','--net',sys.executable,__file__,'--peers',str(count)]+(['--wstunnel'] if wstunnel else []),env)
    if os.environ['UTUN_NET_TEST_ISOLATED']==os.readlink('/proc/self/ns/net'):
        raise RuntimeError('refusing to change networking without a fresh namespace')
    if not Path('/dev/net/tun').exists():
        raise RuntimeError('/dev/net/tun is required')
    processes=[]; nodes=[]; logs=[]; capture=None; stop=threading.Event(); captured=[]
    with tempfile.TemporaryDirectory(prefix='utun-net-') as temp:
        base=Path(temp)
        ws_binary=shutil.which('wstunnel')
        if wstunnel and not ws_binary: raise RuntimeError('wstunnel is required')
        bundles=provision(base/'bundles',count,100000,'10.1.0.0/24','10.50.0.0/24',
                          host='192.0.2.1', server_binary=ws_binary or '/usr/local/bin/wstunnel',
                          client_binary=ws_binary or '/usr/local/bin/wstunnel')
        def wg_config(bundle):
            # Convert generated networkd keys/peer blocks to wg setconf syntax.
            result=[]; active=False
            for line in (bundle/'wg1.netdev').read_text().splitlines():
                if line.startswith('['):
                    active=line in ('[WireGuard]','[WireGuardPeer]')
                    if active: result.append('[Interface]' if line=='[WireGuard]' else '[Peer]')
                elif active: result.append(line)
            path=bundle/'test-setconf.conf';path.write_text('\n'.join(result)+'\n');path.chmod(0o600)
            return path
        def start_ws(bundle, pid=None):
            line=next(l for l in (bundle/'wstunnel-mesh.service').read_text().splitlines() if l.startswith('ExecStart='))
            args=shlex.split(line.split('=',1)[1])
            args[2:2]=['--nb-worker-threads','1']
            if pid: args=['nsenter','-t',str(pid),'-n',*args]
            log=(base/f'ws-{pid or "relay"}.log').open('w+');logs.append(log)
            env={k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy')}
            env['NO_COLOR']='true'
            proc=subprocess.Popen(args,stdout=log,stderr=log,env=env);processes.append(proc)
            return proc
        def ns(pid,*args,**kwargs):
            return run(['nsenter','-t',pid,'-n',*args],**kwargs)
        try:
            run(['ip','link','set','lo','up'])
            Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
            run(['ip','link','add','wg1','type','wireguard'])
            run(['wg','setconf','wg1',wg_config(bundles/'relay')])
            run(['ip','address','add','10.1.0.1/24','dev','wg1'])
            run(['ip','link','set','wg1','up'])
            if wstunnel: start_ws(bundles/'relay')
            run(['ip','link','set','wg1','mtu','1200'])
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
                ns(pid,'ip','link','add','wg1','type','wireguard')
                bundle=bundles/f'peer-{i}'
                ns(pid,'wg','setconf','wg1',wg_config(bundle))
                if wstunnel:
                    if i!=1: ns(pid,'ip','route','add','192.0.2.1/32','via',relay_ip)
                    start_ws(bundle,pid)
                else:
                    relay_pub=(bundles/'relay/wireguard.pub').read_text().strip()
                    ns(pid,'wg','set','wg1','peer',relay_pub,'endpoint',relay_ip+':51872')
                ns(pid,'ip','link','set','wg1','mtu','1200')
                ns(pid,'ip','address','add',f'10.1.0.{i+1}/32','dev','wg1')
                ns(pid,'ip','link','set','wg1','up')
                ns(pid,'ip','route','add','10.1.0.0/24','dev','wg1')
                bundle=bundles/f'peer-{i}'
                ns(pid,'sh',bundle/'setup.sh')
                log=(base/f'node-{i}.log').open('w+');logs.append(log)
                node=subprocess.Popen(['nsenter','-t',str(pid),'-n',str(ROOT/'utun-node'),'-i',str(bundle/'node.ini')],stdout=log,stderr=log)
                processes.append(node);nodes.append(node)
            # Warm up WireGuard handshakes independently of inner key consumption.
            for i,pid in enumerate(peers,1):
                ns(pid,'ping','-n','-c','3','-i','0.2','-W','15','10.1.0.1',stdout=subprocess.DEVNULL)
            capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
            capture.bind(('wg1',0));capture.settimeout(.2)
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
                ns(peers[0],'ping','-n','-c','1','-W','3','-M','do','-s','1100','10.50.0.2',stdout=subprocess.DEVNULL)
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
            for proc in nodes:
                assert proc.poll() is None,'node exited during test'
                proc.send_signal(signal.SIGUSR1)
            print(f'PASS ({"WSS" if wstunnel else "direct WG"}): {count} nodes, {count*(count-1)} directed overlay pings, MTU packet, {len(inner)} encrypted relay packets')
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
    parser.add_argument('--wstunnel',action='store_true')
    args=parser.parse_args()
    if not 2<=args.peers<=32:parser.error('network test supports 2..32 hosts')
    main(args.peers,args.wstunnel)
