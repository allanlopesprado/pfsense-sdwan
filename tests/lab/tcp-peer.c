/*
 * inetd TCP service for the isolated FreeBSD lab. Echo each line together
 * with the peer address observed after NAT. Keep the stream open for callers
 * that verify an established connection across a path change.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	struct sockaddr_in peer;
	socklen_t length = sizeof(peer);
	char address[INET_ADDRSTRLEN];
	char line[128];

	if (getpeername(STDIN_FILENO, (struct sockaddr *)&peer, &length) != 0 ||
	    peer.sin_family != AF_INET ||
	    inet_ntop(AF_INET, &peer.sin_addr, address, sizeof(address)) == NULL)
		return 1;
	while (fgets(line, sizeof(line), stdin) != NULL) {
		if (printf("%s %s", address, line) < 0 || fflush(stdout) == EOF)
			return 1;
	}
	return ferror(stdin) != 0;
}
