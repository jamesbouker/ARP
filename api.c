#include "api.h"
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

UnixDomainSocket * unixDomainSocketMake(UnixDomainSocketType type, int shouldBind, char *init_sun_path) {
	UnixDomainSocket *unixSocket = malloc(sizeof(UnixDomainSocket));
	bzero(unixSocket, sizeof(UnixDomainSocket));

	struct sockaddr_un actualSocket; 
	bzero(&actualSocket, sizeof(actualSocket));
	char buff[MAXLINE];
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	char sun_path[MAXLINE];

	if (type == UnixDomainSocketTypeARP && init_sun_path == NULL) {
		strcpy(buff, "/tmp/-XXXXX");
		int newFd = mkstemp(buff);
		close(newFd);
		strcpy(sun_path, buff);
	}
	else if(type == UnixDomainSocketTypeARP)
		strcpy(sun_path, UNIX_PATH_ARP);
	else if(type == UnixDomainSocketTypeTour)
		strcpy(sun_path, init_sun_path);

	if(fd < 0) {
		printf("error creating socket - terminating...\n");
		exit(1);
	}
	else
		unixSocket->fd = fd;

	strcpy(unixSocket->sun_path, sun_path);
	printf("UnixDomainSocket sun_path: %s\n", unixSocket->sun_path);

	unixDomainSocketUnlink(unixSocket);
	actualSocket.sun_family = AF_UNIX;
	strcpy(actualSocket.sun_path, unixSocket->sun_path);

	if(shouldBind) {
		if(bind(fd, (struct sockaddr *)&actualSocket, sizeof(actualSocket)) < 0) {
			printf("Bind failed in unixSocketMake\n");
			exit(1);
		}
	}

	printf("FD: %d\n", unixSocket->fd);

	return unixSocket;
}

void unixDomainSocketUnlink(UnixDomainSocket * unixSocket) {
	unlink(unixSocket->sun_path);
}

int readFromUnixDomainSocket(int fd, UnixDomainPacket *packet) {
	struct sockaddr_un actualSocket;
	socklen_t addrlen = sizeof(actualSocket);
	return recvfrom(fd, packet, sizeof(UnixDomainPacket), 0, (struct sockaddr *)&actualSocket, &addrlen);
}

void acceptUnixDomainConnection(UnixDomainSocket * unixSocket) {
	struct sockaddr_un sock_addr;
	socklen_t len = sizeof(sock_addr);
	int ret = accept(unixSocket->fd, (struct sockaddr*)&sock_addr, &len);
	if(ret < 0) {
		printf("accept failed: %d\nTerminating...\n", errno);
		exit(1);
    }
    else
    	printf("accepted connection!\n");
}
