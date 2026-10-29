#include <utun/mesh.h>
#include <utun/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static long counter(const char *path)
{
    long n; FILE *f=fopen(path,"rb"); assert(f);
    assert(fread(&n,sizeof(n),1,f)==1); fclose(f); return n;
}
static void packet(unsigned char *p, const struct mesh *src, const struct mesh *dst)
{
    memset(p,0,100); p[0]=0x45; p[3]=100; p[8]=64; p[9]=17;
    memcpy(p+12,&src->address.s_addr,4); memcpy(p+16,&dst->address.s_addr,4);
    memcpy(p+20,"inner traffic must not be readable by relay",42);
}
int main(int argc, char **argv)
{
    assert(argc==2);
    struct mesh m[3]; char path[4096],error[256];
    for (int i=0;i<3;i++) {
        snprintf(path,sizeof(path),"%s/peer-%d/node.ini",argv[1],i+1);
        if (!mesh_load(&m[i],path,error,sizeof(error))) { fprintf(stderr,"%s\n",error); return 1; }
    }
    for (int i=0;i<3;i++) assert(mesh_lock(&m[i]));
    struct mesh duplicate;
    snprintf(path,sizeof(path),"%s/peer-1/node.ini",argv[1]);
    assert(mesh_load(&duplicate,path,error,sizeof(error)));
    assert(!mesh_lock(&duplicate)); /* separate config cannot reuse live keys */
    mesh_free(&duplicate);
    unsigned char p[100],out[1500],wire[1600]; struct mesh_peer *peer;
    /* All six directions must use independent state and reach only their peer. */
    for (int a=0;a<3;a++) for (int b=0;b<3;b++) if (a!=b) {
        packet(p,&m[a],&m[b]);
        int n=mesh_encode(&m[a],p,sizeof(p),wire,sizeof(wire),&peer);
        assert(n==144 && peer && peer->overlay.s_addr==m[b].address.s_addr);
        struct mesh_peer *in=mesh_sender(&m[b],&m[a].bind); assert(in);
        long before=counter(in->in_counter);
        struct sockaddr_in wrong=m[a].bind; wrong.sin_port=htons(1);
        assert(!mesh_decode(&m[b],&wrong,wire,n,out,sizeof(out)));
        assert(counter(in->in_counter)==before);
        /* Even a relay substituting a valid third peer's source cannot select
         * matching material, and rejection cannot consume that peer's keys. */
        int c=3-a-b;
        struct mesh_peer *other=mesh_sender(&m[b],&m[c].bind); assert(other);
        long other_before=counter(other->in_counter);
        assert(!mesh_decode(&m[b],&m[c].bind,wire,n,out,sizeof(out)));
        assert(counter(other->in_counter)==other_before);
        wire[20]^=1;
        assert(!mesh_decode(&m[b],&m[a].bind,wire,n,out,sizeof(out)));
        assert(counter(in->in_counter)==before); wire[20]^=1;
        assert(mesh_decode(&m[b],&m[a].bind,wire,n,out,sizeof(out))==100);
        assert(!memcmp(out,p,100));
        assert(counter(in->in_counter)==counter(peer->out_counter));
        assert(transport_key_remaining(peer->out_key,peer->out_counter)==10000-counter(peer->out_counter));
        assert(!mesh_decode(&m[b],&m[a].bind,wire,n,out,sizeof(out)));
    }
    /* Outgoing spoofed source, unknown destination, bad IP lengths/version,
     * oversized and truncated packets must never consume keys. */
    packet(p,&m[0],&m[1]);
    peer=mesh_destination(&m[0],p,100); assert(peer);
    long before=counter(peer->out_counter);
    memcpy(p+12,&m[2].address.s_addr,4);
    assert(!mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer));
    packet(p,&m[0],&m[1]); p[16]=192;
    assert(!mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer));
    packet(p,&m[0],&m[1]); p[0]=0x65;
    assert(!mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer));
    p[0]=0x44; assert(!mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer));
    p[0]=0x45; p[3]=99; assert(!mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer));
    assert(!mesh_encode(&m[0],p,10,wire,sizeof(wire),&peer));
    assert(!mesh_encode(&m[0],p,1500,wire,sizeof(wire),&peer));
    packet(p,&m[0],&m[1]); peer=mesh_destination(&m[0],p,100);
    assert(counter(peer->out_counter)==before);
    /* A legitimately authenticated neighbour cannot claim a third host's
     * source, nor make us a transit router by targeting another destination. */
    char plain[102]; plain[0]=1; plain[1]=0;
    for (int mode=0;mode<2;mode++) {
        packet(p,&m[0],&m[1]);
        memcpy(p+(mode?16:12),&m[2].address.s_addr,4);
        memcpy(plain+2,p,100);
        int n=encryptpacket(plain,sizeof(plain),wire,sizeof(wire),peer->out_key,peer->out_counter);
        assert(n>0); memset(out,0xab,sizeof(out));
        assert(!mesh_decode(&m[1],&m[0].bind,wire,n,out,sizeof(out)));
        assert(out[0]==0xab); /* no plaintext delivered */
    }
    /* Data can pass unchanged through an opaque UDP forwarder. Endpoint
     * identity is supplied by routing in production (no SNAT). */
    int relay=socket_create(0), receiver=socket_create(0), sender=socket_create(0);
    struct sockaddr_in relay_addr,recv_addr,source;
    socklen_t len=sizeof(relay_addr);
    assert(!getsockname(relay,(struct sockaddr *)&relay_addr,&len));
    len=sizeof(recv_addr); assert(!getsockname(receiver,(struct sockaddr *)&recv_addr,&len));
    relay_addr.sin_addr.s_addr=recv_addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    packet(p,&m[0],&m[1]);
    int n=mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer); assert(n>0);
    assert(sendto(sender,wire,n,0,(struct sockaddr *)&relay_addr,sizeof(relay_addr))==n);
    unsigned char opaque[1600]; len=sizeof(source);
    assert(recvfrom(relay,opaque,sizeof(opaque),0,(struct sockaddr *)&source,&len)==n);
    assert(!memcmp(opaque,wire,n));
    assert(sendto(relay,opaque,n,0,(struct sockaddr *)&recv_addr,sizeof(recv_addr))==n);
    assert(recv(receiver,opaque,sizeof(opaque),0)==n);
    assert(mesh_decode(&m[1],&m[0].bind,opaque,n,out,sizeof(out))==100);
    assert(!memcmp(out,p,100)); close(relay); close(receiver); close(sender);
    /* Exhausting one link must neither emit a packet nor stall another link. */
    packet(p,&m[0],&m[1]); peer=mesh_destination(&m[0],p,100);
    before=counter(peer->out_counter);
    assert(!truncate(peer->out_key,before));
    assert(!mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer));
    assert(counter(peer->out_counter)==before);
    assert(transport_key_remaining(peer->out_key,peer->out_counter)==0);
    packet(p,&m[0],&m[2]);
    n=mesh_encode(&m[0],p,100,wire,sizeof(wire),&peer); assert(n>0);
    assert(mesh_decode(&m[2],&m[0].bind,wire,n,out,sizeof(out))==100);
    for (int i=0;i<3;i++) mesh_free(&m[i]);
    puts("mesh isolation, routing, replay, and opaque forwarding tests passed");
}
