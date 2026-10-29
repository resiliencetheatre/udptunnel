/*
 * udptunnel
 * Copyright © 2013 Felipe Astroza A.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utun/socket.h>
#include <utun/tun.h>
#include <utun/util.h>
#include <utun/tunnel_packet.h>
#include <unistd.h>
#include "log.h"
#include "ini.h"

int main(int argc, char *argv[])
{
	struct sockaddr_in client_addr, from;
	socklen_t fromlen;
	fd_set rfds;
	struct tunnel_packet *tp;
	char buf[MTU];
	unsigned int buflen;
	unsigned short local_port;
	int ret;
	int tun_fd;
	int client_fd;
	int has_client = 0;

	int log_level=LOG_INFO;
	int c=0;
	char *ini_file=NULL;
	char *server_port=NULL;

	char *outbound_key = NULL;
	char *inbound_key = NULL;
	char *outbound_counter = NULL;
	char *inbound_counter = NULL;

	tp = (struct tunnel_packet *)buf;

	/* ini-file */
	while ((c = getopt (argc, argv, "dhi:")) != -1)
	switch (c)
	{
		case 'd':
			log_level=LOG_DEBUG;
			break;
		case 'i':
			ini_file = optarg;
			break;
		case 'h':
			log_info("[%d] server",getpid());
			log_info("[%d] Usage: -i [ini_file] ",getpid());
			log_info("[%d]        -d debug log ",getpid());
			return 1;
		break;
			default:
			break;
	}
	if (ini_file == NULL)
	{
		log_error("[%d] ini file not specified, exiting. ", getpid());
		return 1;
	}

	log_set_level(log_level);

	ini_t *config = ini_load(ini_file);
	if (config == NULL ) {
		log_error("[%d] Cannot open ini-file, exiting.", getpid());
		return 1;
	}
	ini_sget(config, "server", "server_port", NULL, &server_port);

	ini_sget(config, "server", "outbound_key", NULL, &outbound_key);
	ini_sget(config, "server", "inbound_key", NULL, &inbound_key);
	ini_sget(config, "server", "outbound_counter_file", NULL, &outbound_counter);
	ini_sget(config, "server", "inbound_counter_file", NULL, &inbound_counter);
	log_info("[%d] Server port %s",getpid(),server_port ? server_port : "(missing)");


	if (!server_port ||
        !transport_config_valid(outbound_key, outbound_counter) ||
        !transport_config_valid(inbound_key, inbound_counter) ||
        !transport_files_distinct(outbound_key, inbound_key, outbound_counter, inbound_counter)) {
        log_error("Invalid configuration: supply distinct directional keys and valid binary counters");
        return 1;
    }

	if(strtoport(server_port, &local_port) == 0) {
		log_error("[%d] Invalid port: %s",getpid(),server_port ? server_port : "(missing)");
		return 1;
	}


	tun_fd = tun_create();
	client_fd = socket_create(local_port);
	fromlen = sizeof(from);
	exec_script("linux_server.sh", server_port);
	FD_ZERO(&rfds);

	log_info("[%d] Server ready ",getpid());
	while(1) {
		FD_SET(client_fd, &rfds);
		FD_SET(tun_fd, &rfds);
		ret = select(client_fd+1, &rfds, NULL, NULL, NULL);

		if(ret == -1)
			break;

		if(FD_ISSET(tun_fd, &rfds)) {
			int n = tun_get_packet(tun_fd, tp->data, sizeof(buf)-sizeof(struct tunnel_packet));
            if (n <= 0) continue;
            buflen = (unsigned int)n;
			tp->type = TRAFFIC_PACKET;
			tp->cmd = 0;
			if(has_client) {
				socket_put_packet(client_fd, &client_addr, sizeof(client_addr), buf, buflen + sizeof(struct tunnel_packet),outbound_key,outbound_counter);
			}
		}
		if(FD_ISSET(client_fd, &rfds)) {
			buflen = socket_get_packet(client_fd, &from, &fromlen, buf, sizeof(buf),inbound_key,inbound_counter,has_client ? &client_addr : NULL);
            if (buflen < sizeof(struct tunnel_packet)) continue;
            if (!has_client) {
                client_addr = from;
                has_client = 1;
            }
            tun_put_packet(tun_fd, tp->data, buflen-sizeof(struct tunnel_packet));
		}
	}
	return 1;
}
