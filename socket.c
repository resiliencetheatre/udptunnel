/* UDP tunnel packet transport. The wire header has no protocol signature. */
#include <utun/socket.h>
#include <utun/tunnel_packet.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "log.h"

#define HEADER 10
#define TAG 32
#define WIRE_MAX (HEADER + MTU + TAG)

static int read_counter(const char *path, long *value)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int ok = fread(value, sizeof(*value), 1, f) == 1 &&
             fgetc(f) == EOF && !ferror(f) && *value >= 0;
    fclose(f);
    return ok;
}

/* Rename prevents a crash from leaving a partially written counter. */
static int write_counter(const char *path, long value)
{
    size_t n = strlen(path) + 12;
    char *tmp = malloc(n);
    if (!tmp) return 0;
    snprintf(tmp, n, "%s.XXXXXX", path);
    int fd = mkstemp(tmp);
    int ok = fd >= 0;
    if (ok) {
        ok = write(fd, &value, sizeof(value)) == sizeof(value) && fsync(fd) == 0;
        if (close(fd) != 0) ok = 0;
    }
    if (ok) ok = rename(tmp, path) == 0;
    if (ok) {
        char *slash = strrchr(tmp, '/');
        if (slash == tmp) slash[1] = '\0';
        else if (slash) *slash = '\0';
        int dir = open(slash ? tmp : ".", O_RDONLY | O_DIRECTORY);
        ok = dir >= 0 && fsync(dir) == 0;
        if (dir >= 0) close(dir);
        /* A failed directory sync leaves the reservation in place. */
        free(tmp);
        return ok;
    }
    if (!ok) unlink(tmp);
    free(tmp);
    return ok;
}

long long transport_key_remaining(const char *key, const char *counter)
{
    struct stat st;
    long next;
    if (!key || !counter || stat(key,&st) || !S_ISREG(st.st_mode) ||
        !read_counter(counter,&next) || next>st.st_size) return -1;
    return st.st_size-next;
}

int transport_config_valid(const char *key, const char *counter)
{
    struct stat st;
    long index;
    int fd;
    if (!key || !counter || !strcmp(key, counter)) return 0;
    fd = open(key, O_RDWR);
    if (fd < 0) return 0;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
             read_counter(counter, &index) && index <= st.st_size &&
             st.st_size - index >= TAG + 2;
    close(fd);
    return ok;
}

int transport_files_distinct(const char *a, const char *b, const char *c, const char *d)
{
    const char *paths[] = {a, b, c, d};
    struct stat st[4];
    for (int i = 0; i < 4; ++i) {
        if (!paths[i] || stat(paths[i], &st[i]) || !S_ISREG(st[i].st_mode)) return 0;
        for (int j = 0; j < i; ++j)
            if (st[i].st_dev == st[j].st_dev && st[i].st_ino == st[j].st_ino) return 0;
    }
    return 1;
}

static int open_key(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd >= 0 && flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int read_key(int fd, long offset, unsigned char *key, size_t size)
{
    struct stat st;
    if (offset < 0 || size > (size_t)(LONG_MAX - offset) || fstat(fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || offset > st.st_size || size > (size_t)(st.st_size-offset)) return 0;
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, key + done, size - done, offset + done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        done += n;
    }
    return 1;
}

static int commit_key(int fd, const char *counter, long offset, size_t size)
{
    /* Reserve first: an erasure failure must never permit key reuse. */
    if (!write_counter(counter, offset + size)) return 0;
    unsigned char zeros[MTU + TAG] = {0};
    size_t done = 0;
    while (done < size) {
        ssize_t n = pwrite(fd, zeros + done, size - done, offset + done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        done += n;
    }
    return fsync(fd) == 0;
}

static int mac(const unsigned char *key, const unsigned char *data, size_t n, unsigned char *tag)
{
    unsigned int len = 0;
    return HMAC(EVP_sha256(), key, TAG, data, n, tag, &len) != NULL && len == TAG;
}

int encryptpacket(const char *buf, unsigned int len, unsigned char *wire,
                  size_t capacity, const char *keyfile, const char *counter)
{
    unsigned char key[MTU + TAG];
    long index;
    int result = 0, fd = -1;
    if (len < 2 || len > MTU || capacity < HEADER + len + TAG) return 0;
    fd = open_key(keyfile);
    if (fd < 0 || !read_counter(counter, &index) ||
        !read_key(fd, index, key, len + TAG)) goto out;
    uint64_t pos = index;
    for (int i = 7; i >= 0; --i) { wire[i] = pos & 255; pos >>= 8; }
    wire[8] = len >> 8; wire[9] = len & 255;
    for (unsigned int i = 0; i < len; ++i) wire[HEADER+i] = (unsigned char)buf[i] ^ key[i];
    if (!mac(key + len, wire, HEADER + len, wire + HEADER + len) ||
        !commit_key(fd, counter, index, len + TAG)) goto out;
    result = HEADER + len + TAG;
out:
    OPENSSL_cleanse(key, sizeof(key));
    if (fd >= 0) close(fd);
    return result;
}

int decryptpacket(char *buf, size_t capacity, const unsigned char *wire,
                  size_t bytes, const char *keyfile, const char *counter)
{
    unsigned char key[MTU + TAG], tag[TAG], plain[MTU];
    int fd = -1, result = 0;
    long next;
    if (bytes < HEADER + 2 + TAG) return 0;
    unsigned int len = ((unsigned int)wire[8] << 8) | wire[9];
    if (len < 2 || len > MTU || len > capacity || bytes != HEADER + len + TAG) return 0;
    uint64_t index = 0;
    for (int i = 0; i < 8; ++i) index = (index << 8) | wire[i];
    if (index > LONG_MAX) return 0;
    fd = open_key(keyfile);
    if (fd < 0 || !read_counter(counter, &next) || index < (uint64_t)next ||
        !read_key(fd, (long)index, key, len + TAG)) goto out;
    if (!mac(key + len, wire, HEADER + len, tag) ||
        CRYPTO_memcmp(tag, wire + HEADER + len, TAG)) goto out;
    for (unsigned int i = 0; i < len; ++i) plain[i] = wire[HEADER+i] ^ key[i];
    if (plain[0] != TRAFFIC_PACKET || plain[1] != 0) goto out;
    if (!commit_key(fd, counter, index, len + TAG)) goto out;
    memcpy(buf, plain, len);
    result = len;
out:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plain, sizeof(plain));
    if (fd >= 0) close(fd);
    return result;
}

int socket_create(unsigned short port)
{
    struct sockaddr_in sa = {0};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = port;
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("UDP socket"); exit(1);
    }
    return fd;
}

void socket_put_packet(int fd, struct sockaddr_in *sa, socklen_t salen,
                       char *buf, unsigned int len, char *key, char *counter)
{
    unsigned char wire[WIRE_MAX];
    int n = encryptpacket(buf, len, wire, sizeof(wire), key, counter);
    if (!n) { log_error("Cannot encrypt packet: check key material and counter file"); return; }
    if (sendto(fd, wire, n, 0, (struct sockaddr *)sa, salen) != n)
        log_error("sendto: %s", strerror(errno));
}

unsigned int socket_get_packet(int fd, struct sockaddr_in *sa, socklen_t *salen,
                               char *buf, unsigned int capacity, char *key, char *counter,
                               const struct sockaddr_in *peer)
{
    /* One extra byte makes oversized datagrams unambiguously invalid. */
    unsigned char wire[WIRE_MAX + 1];
    socklen_t addrlen = sizeof(*sa);
    ssize_t n = recvfrom(fd, wire, sizeof(wire), 0, (struct sockaddr *)sa, &addrlen);
    if (salen) *salen = addrlen;
    if (n <= 0 || n > WIRE_MAX) return 0;
    if (peer && (peer->sin_addr.s_addr != sa->sin_addr.s_addr || peer->sin_port != sa->sin_port)) return 0;
    return decryptpacket(buf, capacity, wire, n, key, counter);
}
