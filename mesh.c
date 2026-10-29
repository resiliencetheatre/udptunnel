#define _GNU_SOURCE
/* Static IPv4 full-mesh routing over independently authenticated UDP links. */
#include <utun/mesh.h>
#include <utun/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "ini.h"

static int number(const char *s, unsigned min, unsigned max, unsigned *out)
{
    if (!s || !*s) return 0;
    for (const char *p=s; *p; p++) if (!isdigit((unsigned char)*p)) return 0;
    errno=0; char *end; unsigned long n=strtoul(s,&end,10);
    if (errno || *end || n<min || n>max) return 0;
    *out=(unsigned)n; return 1;
}
static int address(const char *s, struct in_addr *a)
{
    return s && inet_pton(AF_INET,s,a)==1;
}
static int overlay(const char *s, struct in_addr *a)
{
    if (!address(s,a)) return 0;
    unsigned v=ntohl(a->s_addr);
    return v && (v>>24)!=127 && (v>>24)!=0 && (v>>24)<224;
}
static char *path(const char *base, const char *value)
{
    if (!value || !*value) return NULL;
    if (*value=='/') return strdup(value);
    size_t n=strlen(base)+strlen(value)+2;
    char *p=malloc(n);
    if (p) snprintf(p,n,"%s/%s",base,value);
    return p;
}
void mesh_free(struct mesh *m)
{
    for (size_t i=0; i<m->count; i++) {
        free(m->peers[i].out_key); free(m->peers[i].in_key);
        free(m->peers[i].out_counter); free(m->peers[i].in_counter);
    }
    if (m->key_locks) {
        for (size_t i=0;i<2*m->count;i++) if (m->key_locks[i]>=0) close(m->key_locks[i]);
        free(m->key_locks);
    }
    free(m->peers); memset(m,0,sizeof(*m));
}
/* Linux open-file-description locks survive transport opens/closes and are
 * independent of the per-packet flock transactions. Hold each key inode for the
 * lifetime of the node, including when another config uses a hardlink alias. */
int mesh_lock(struct mesh *m)
{
    if (m->key_locks) return 0;
    int *fds=malloc(2*m->count*sizeof(*fds));
    if (!fds) return 0;
    for (size_t i=0;i<2*m->count;i++) fds[i]=-1;
    for (size_t i=0;i<2*m->count;i++) {
        struct mesh_peer *p=&m->peers[i/2];
        fds[i]=open(i%2?p->in_key:p->out_key,O_RDWR|O_CLOEXEC);
        struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0};
        if (fds[i]<0 || fcntl(fds[i],F_OFD_SETLK,&lock)<0) {
            for (size_t j=0;j<=i;j++) if (fds[j]>=0) close(fds[j]);
            free(fds); return 0;
        }
    }
    m->key_locks=fds; return 1;
}
int mesh_load(struct mesh *m, const char *file, char *error, size_t error_size)
{
    memset(m,0,sizeof(*m));
    ini_t *ini=NULL;
    char *base=NULL;
    struct stat *seen=NULL;
    const char *why="cannot read configuration";
    size_t used=0;
    unsigned count,port;
    base=realpath(file,NULL);
    if (!base || !(ini=ini_load(base))) goto fail;
    char *slash=strrchr(base,'/');
    if (slash==base) slash[1]='\0'; else if (slash) *slash='\0';
    const char *name=ini_get(ini,"node","interface");
    why="invalid node interface, address, bind_address, port, mtu, or peer_count";
    if (!name || !*name || strlen(name)>=IFNAMSIZ || !strcmp(name,".") || !strcmp(name,"..")) goto fail;
    for (const char *p=name;*p;p++)
        if (!isalnum((unsigned char)*p) && *p!='-' && *p!='_' && *p!='.') goto fail;
    strcpy(m->interface,name);
    if (!overlay(ini_get(ini,"node","address"),&m->address) ||
        !address(ini_get(ini,"node","bind_address"),&m->bind.sin_addr) ||
        !number(ini_get(ini,"node","port"),1,65535,&port) ||
        !number(ini_get(ini,"node","mtu"),576,MESH_MAX_PACKET,&m->mtu) ||
        !number(ini_get(ini,"node","peer_count"),1,MESH_MAX_PEERS,&count)) goto fail;
    if (m->bind.sin_addr.s_addr==m->address.s_addr ||
        (ntohl(m->bind.sin_addr.s_addr)>>24)>=224) goto fail;
    m->bind.sin_family=AF_INET; m->bind.sin_port=htons(port);
    why="out of memory";
    m->peers=calloc(count,sizeof(*m->peers));
    seen=calloc(count*4,sizeof(*seen));
    if (!m->peers || !seen) goto fail;
    m->count=count;
    for (size_t i=0;i<m->count;i++) {
        struct mesh_peer *p=&m->peers[i];
        char section[32]; snprintf(section,sizeof(section),"peer%zu",i+1);
        why="invalid peer address, endpoint, or port (expected peer1 through peer_count)";
        if (!overlay(ini_get(ini,section,"address"),&p->overlay) ||
            p->overlay.s_addr==m->address.s_addr ||
            !overlay(ini_get(ini,section,"endpoint"),&p->endpoint.sin_addr) ||
            !number(ini_get(ini,section,"port"),1,65535,&port)) goto fail;
        p->endpoint.sin_family=AF_INET; p->endpoint.sin_port=htons(port);
        why="duplicate peer overlay address or UDP endpoint";
        for (size_t j=0;j<i;j++)
            if (p->overlay.s_addr==m->peers[j].overlay.s_addr ||
                (p->endpoint.sin_addr.s_addr==m->peers[j].endpoint.sin_addr.s_addr &&
                 p->endpoint.sin_port==m->peers[j].endpoint.sin_port)) goto fail;
        p->out_key=path(base,ini_get(ini,section,"outbound_key"));
        p->in_key=path(base,ini_get(ini,section,"inbound_key"));
        p->out_counter=path(base,ini_get(ini,section,"outbound_counter_file"));
        p->in_counter=path(base,ini_get(ini,section,"inbound_counter_file"));
        why="invalid key/counter files or exhausted key material";
        if (!transport_config_valid(p->out_key,p->out_counter) ||
            !transport_config_valid(p->in_key,p->in_counter)) goto fail;
        const char *paths[]={p->out_key,p->in_key,p->out_counter,p->in_counter};
        why="all key/counter files must be distinct regular files across every peer";
        for (size_t k=0;k<4;k++) {
            if (!paths[k] || stat(paths[k],&seen[used]) || !S_ISREG(seen[used].st_mode)) goto fail;
            for (size_t j=0;j<used;j++)
                if (seen[j].st_dev==seen[used].st_dev && seen[j].st_ino==seen[used].st_ino) goto fail;
            used++;
        }
    }
    /* An overlay host route must never capture a UDP transport endpoint. */
    why="overlay and transport host addresses overlap";
    for (size_t i=0;i<m->count;i++) {
        if (m->peers[i].endpoint.sin_addr.s_addr==m->address.s_addr ||
            m->peers[i].overlay.s_addr==m->bind.sin_addr.s_addr) goto fail;
        for (size_t j=0;j<m->count;j++)
            if (m->peers[i].overlay.s_addr==m->peers[j].endpoint.sin_addr.s_addr) goto fail;
    }
    free(seen); free(base); ini_free(ini); return 1;
fail:
    if (error_size) snprintf(error,error_size,"%s",why);
    free(seen); free(base); if (ini) ini_free(ini); mesh_free(m); return 0;
}
/* TUN carries bare IPv4. Validate lengths before inspecting source/destination.
 * Fragmented IPv4 is allowed; routing does not inspect transport headers. */
static int ip(const unsigned char *p, size_t n)
{
    if (n<20 || (p[0]>>4)!=4) return 0;
    unsigned ihl=(p[0]&15)*4;
    return ihl>=20 && ihl<=n && (((unsigned)p[2]<<8)|p[3])==n;
}
struct mesh_peer *mesh_destination(struct mesh *m, const unsigned char *p, size_t n)
{
    if (n>m->mtu || !ip(p,n) || memcmp(p+12,&m->address.s_addr,4)) return NULL;
    for (size_t i=0;i<m->count;i++)
        if (!memcmp(p+16,&m->peers[i].overlay.s_addr,4)) return &m->peers[i];
    return NULL;
}
struct mesh_peer *mesh_sender(struct mesh *m, const struct sockaddr_in *from)
{
    if (from->sin_family!=AF_INET) return NULL;
    for (size_t i=0;i<m->count;i++)
        if (from->sin_addr.s_addr==m->peers[i].endpoint.sin_addr.s_addr &&
            from->sin_port==m->peers[i].endpoint.sin_port) return &m->peers[i];
    return NULL;
}
int mesh_encode(struct mesh *m, const unsigned char *packet, size_t n,
                unsigned char *wire, size_t capacity, struct mesh_peer **dest)
{
    *dest=mesh_destination(m,packet,n);
    if (!*dest) return 0;
    struct mesh_peer *p=*dest;
    char plain[MESH_MAX_PACKET+2]; plain[0]=1; plain[1]=0;
    memcpy(plain+2,packet,n);
    int result=encryptpacket(plain,n+2,wire,capacity,p->out_key,p->out_counter);
    OPENSSL_cleanse(plain,sizeof(plain));
    if (!result) p->rejected++;
    return result;
}
int mesh_decode(struct mesh *m, const struct sockaddr_in *from,
                const unsigned char *wire, size_t n, unsigned char *packet, size_t capacity)
{
    struct mesh_peer *p=mesh_sender(m,from);
    if (!p) return 0;
    char plain[MESH_MAX_PACKET+2];
    int result=decryptpacket(plain,sizeof(plain),wire,n,p->in_key,p->in_counter);
    if (result<22 || (size_t)(result-2)>capacity || (unsigned)(result-2)>m->mtu ||
        !ip((unsigned char *)plain+2,result-2) ||
        memcmp(plain+14,&p->overlay.s_addr,4) ||
        memcmp(plain+18,&m->address.s_addr,4)) {
        OPENSSL_cleanse(plain,sizeof(plain));
        p->rejected++; return 0;
    }
    memcpy(packet,plain+2,result-2);
    OPENSSL_cleanse(plain,sizeof(plain));
    p->received++; return result-2;
}
