#include "tour.h"
#include "api.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, hwaddr *HWaddr) {
	UnixDomainSocket *arpSocket = arpSocket = unixDomainSocketMake(UnixDomainSocketTypeARP, 1, NULL);
	UnixDomainPacket packet;
	bzero(&packet, sizeof(packet));
	struct sockaddr_un sock_addr;
	strcpy(sock_addr.sun_path, UNIX_PATH_ARP);
	sock_addr.sun_family = AF_LOCAL;
	int len = sizeof(sock_addr);
	struct sockaddr_in * addrPtr = (struct sockaddr_in *)IPaddr;
	inet_ntop(AF_INET , &addrPtr->sin_addr, packet.destIpAddress, 16);
	printf("ip from inet_ntop: %s\n", packet.destIpAddress);

	int ret = connect(arpSocket->fd, (struct sockaddr * )&sock_addr, len);
	if(ret < 0) 
		printf("connect failed: %d\n", errno);

	ret = send(arpSocket->fd, &packet, sizeof(packet), 0);
	if(ret < 0)
		printf("send error: %d\n", errno);

	fd_set set;
	while(1) {
		FD_ZERO(&set);
		FD_SET(arpSocket->fd, &set);

		struct timeval tv = {10, 0};
		printf("entering select\n");
		ret = select(arpSocket->fd + 1, &set, NULL, NULL, &tv);
		
		if(ret > 0) {
			printf("select returned: %d\n", ret);
			if(FD_ISSET(arpSocket->fd, &set)) {
				printf("FD_ISSET: Attempt to read here!\n");
				UnixDomainPacket returnPacket; bzero(&returnPacket, sizeof(returnPacket));
				readFromUnixDomainSocket(arpSocket->fd, &returnPacket);
				printPacket(&returnPacket);
			}
		}
		else if(ret == 0) {
			printf("Timeout\n");
		}
		else {
			printf("select error\n");
		}
	}
}

void setup() {

}

int main(int argc, char **argv) {
	setup();


	struct sockaddr_in sock_addr;
	hwaddr hw_addr;
	bzero(&hw_addr, sizeof(hw_addr));
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &sock_addr.sin_addr);
	areq((struct sockaddr*) &sock_addr, -1, &hw_addr);


	exit(1);
}