#ifndef UTUN_MESH_H
#define UTUN_MESH_H
#include <net/if.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#define MESH_MAX_PEERS 1024
#define MESH_MAX_PACKET 1498
struct mesh_peer {
    struct in_addr overlay;
    struct sockaddr_in endpoint;
    char *out_key, *in_key, *out_counter, *in_counter;
    uint64_t sent, received, rejected;
};
struct mesh {
    char interface[IFNAMSIZ];
    struct in_addr address;
    struct sockaddr_in bind;
    unsigned mtu;
    size_t count;
    struct mesh_peer *peers;
    int *key_locks;
};
int mesh_load(struct mesh *, const char *, char *, size_t);
void mesh_free(struct mesh *);
int mesh_lock(struct mesh *);
struct mesh_peer *mesh_destination(struct mesh *, const unsigned char *, size_t);
struct mesh_peer *mesh_sender(struct mesh *, const struct sockaddr_in *);
int mesh_encode(struct mesh *, const unsigned char *, size_t, unsigned char *, size_t, struct mesh_peer **);
int mesh_decode(struct mesh *, const struct sockaddr_in *, const unsigned char *, size_t, unsigned char *, size_t);
#endif
