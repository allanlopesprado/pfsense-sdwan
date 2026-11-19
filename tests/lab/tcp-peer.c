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
	struct sockaddr_storage peer;
	socklen_t length = sizeof(peer);
	const void *source;
	char address[INET6_ADDRSTRLEN];
	char line[128];

	if (getpeername(STDIN_FILENO, (struct sockaddr *)&peer, &length) != 0)
		return 1;
	switch (peer.ss_family) {
	case AF_INET:
		source = &((struct sockaddr_in *)&peer)->sin_addr;
		break;
	case AF_INET6:
		source = &((struct sockaddr_in6 *)&peer)->sin6_addr;
		break;
	default:
		return 1;
	}
	if (inet_ntop(peer.ss_family, source, address, sizeof(address)) == NULL)
		return 1;
	while (fgets(line, sizeof(line), stdin) != NULL) {
		if (printf("%s %s", address, line) < 0 || fflush(stdout) == EOF)
			return 1;
	}
	return ferror(stdin) != 0;
}
