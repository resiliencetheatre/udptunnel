/* UDP Tunnel - socket.h
 * 2009 - Felipe Astroza
 * Under GPLv2 license (see LICENSE)
 */

#ifndef SOCKET_H
#define SOCKET_H
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

int transport_files_distinct(const char *, const char *, const char *, const char *);
int transport_config_valid(const char *, const char *);
int encryptpacket(const char *, unsigned int, unsigned char *, size_t, const char *, const char *);
int decryptpacket(char *, size_t, const unsigned char *, size_t, const char *, const char *);

int socket_create(unsigned short port);
void socket_put_packet(int fd, struct sockaddr_in *sa, socklen_t salen, char *buf, unsigned int buflen, char* keyfile, char* outbound_counter_file);
unsigned int socket_get_packet(int fd, struct sockaddr_in *sa, socklen_t *salen, char *buf, unsigned int bufsize, char* keyfile, char* inbound_counter_file, const struct sockaddr_in *peer);

#endif
