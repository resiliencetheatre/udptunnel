/* One shared TUN and one UDP socket; the relay never terminates inner crypto. */
#include <utun/mesh.h>
#include <utun/tun.h>
#include <utun/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include "log.h"
static volatile sig_atomic_t stopping, report;
static void signal_handler(int sig)
{
    if (sig==SIGUSR1) report=1; else stopping=1;
}
static void status(struct mesh *m)
{
    for (size_t i=0;i<m->count;i++) {
        struct mesh_peer *p=&m->peers[i]; char a[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&p->overlay,a,sizeof(a));
        log_info("peer %s: sent=%" PRIu64 " received=%" PRIu64 " rejected=%" PRIu64,
                 a,p->sent,p->received,p->rejected);
        log_info("peer %s: remaining out=%lld in=%lld key bytes (-1 means unreadable)",
                 a,transport_key_remaining(p->out_key,p->out_counter),
                 transport_key_remaining(p->in_key,p->in_counter));
    }
}
int main(int argc, char **argv)
{
    int opt,check=0,udp=-1,tun=-1,lock=-1,result=1;
    const char *config=NULL;
    while ((opt=getopt(argc,argv,"i:ch"))!=-1) {
        if (opt=='i') config=optarg;
        else if (opt=='c') check=1;
        else { fprintf(stderr,"Usage: node -i node.ini [-c (validate only)]\n"); return opt=='h'?0:1; }
    }
    if (!config || optind!=argc) { fprintf(stderr,"Specify -i node.ini\n"); return 1; }
    struct mesh m; char error[256];
    if (!mesh_load(&m,config,error,sizeof(error))) { log_error("Configuration: %s",error); return 1; }
    if (check) { printf("Valid configuration: %zu peers, interface %s, MTU %u\n",m.count,m.interface,m.mtu); mesh_free(&m); return 0; }
    /* Protect against accidentally running this bundle twice. State must not be
     * shared with other bundles/processes; configuration inode aliases lock too. */
    lock=open(config,O_RDONLY);
    if (lock<0 || flock(lock,LOCK_EX|LOCK_NB)) { log_error("Cannot lock configuration (already running?)"); goto done; }
    if (!mesh_lock(&m)) { log_error("Cannot exclusively lock peer keys (in use or inaccessible)"); goto done; }
    udp=socket(AF_INET,SOCK_DGRAM,0);
    if (udp<0 || bind(udp,(struct sockaddr *)&m.bind,sizeof(m.bind))) { perror("bind UDP"); goto done; }
    tun=tun_create_named(m.interface);
    if (tun<0) { perror("create TUN"); goto done; }
    struct sigaction action={0}; action.sa_handler=signal_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT,&action,NULL); sigaction(SIGTERM,&action,NULL); sigaction(SIGUSR1,&action,NULL);
    log_info("Node ready: %zu peers on %s; configure its address/routes with setup.sh",m.count,m.interface);
    struct pollfd fds[]={{tun,POLLIN,0},{udp,POLLIN,0}};
    unsigned char packet[MESH_MAX_PACKET+1],wire[MESH_MAX_PACKET+2+42+1];
    result=0;
    while (!stopping) {
        if (report) { report=0; status(&m); }
        int ready=poll(fds,2,1000);
        if (ready<0) { if (errno==EINTR) continue; perror("poll"); result=1; break; }
        if ((fds[0].revents|fds[1].revents)&(POLLERR|POLLHUP|POLLNVAL)) {
            log_error("TUN/UDP descriptor failed"); result=1; break;
        }
        if (fds[0].revents&POLLIN) {
            ssize_t n=read(tun,packet,sizeof(packet));
            if (n<0 && errno!=EINTR) { perror("read TUN"); result=1; break; }
            if (n>0) {
                struct mesh_peer *p;
                int bytes=mesh_encode(&m,packet,n,wire,sizeof(wire),&p);
                if (bytes) {
                    if (sendto(udp,wire,bytes,0,(struct sockaddr *)&p->endpoint,sizeof(p->endpoint))!=bytes)
                        { log_error("sendto: %s (reserved key bytes remain consumed)",strerror(errno)); p->rejected++; }
                    else p->sent++;
                } else if (p) log_error("Peer encryption failed: key exhausted or state I/O failure");
            }
        }
        if (fds[1].revents&POLLIN) {
            struct sockaddr_in from; socklen_t len=sizeof(from);
            ssize_t n=recvfrom(udp,wire,sizeof(wire),0,(struct sockaddr *)&from,&len);
            if (n<0 && errno!=EINTR) { perror("recvfrom"); result=1; break; }
            if (n>0) {
                int bytes=mesh_decode(&m,&from,wire,n,packet,sizeof(packet));
                if (bytes && write(tun,packet,bytes)!=bytes) { perror("write TUN"); result=1; break; }
            }
        }
    }
    status(&m);
done:
    if (tun>=0) close(tun);
    if (udp>=0) close(udp);
    if (lock>=0) close(lock);
    mesh_free(&m); return result;
}
