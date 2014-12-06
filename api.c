#include "api.h"
#include "api.h"
#include "prhwaddrs.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

void rawPacketBuffer(RawPacket *packetPtr, char *buffer) {
	RawPacket packet = packetPtr[0];
	int i, j=0;
	for(i=0; i<6; i++)
		buffer[j++] = packet.destHWAddr[i];
	for(i=0; i<6; i++)
		buffer[j++] = packet.sourceHWAddr[i];
	buffer[j++] = packet.protocolNum / 256;
	buffer[j++] = packet.protocolNum % 256;
	char *unixPacketPtr = (char*)&packet.unixPacket;
	for(i=0; i<sizeof(packet.unixPacket); i++)
		buffer[j++] = unixPacketPtr[i];
}

void printInterface(Interface inf) {
	printf("Interface: %s\n", inf.if_name);
	printf("if_index: %d\n", inf.if_index);
	printf("ip_addr: %s\n", inf.ip_addr);
}

Interface getEth0() {
	struct 	hwa_info *hwa;
	struct 	sockaddr *sa;
	Interface eth0;
	bzero(&eth0, sizeof(eth0));
	for (hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
		sa = hwa->ip_addr;
		if(strcmp(hwa->if_name, "eth0") == 0) {
			char *ip_addr = sock_ntop_host(sa, sizeof(*sa));
			strcpy(eth0.ip_addr, ip_addr);
			strcpy(eth0.if_name, hwa->if_name);
			eth0.if_index = hwa->if_index;
			int i;
			for(i=0; i<6; i++)
				eth0.hw_addr[i] = hwa->if_haddr[i];
		}
	}
	return eth0;
}

void ipForVm(char *vmName, char *ip) {
	//TODO: This needs to be rewritted to use something dynamic
	char ipHolder[16]; 
	bzero(ipHolder, sizeof(ipHolder));
	strcpy(ipHolder, "130.245.156.20");
	ipHolder[13] = vmName[2];
	if(strlen(vmName) > 3 && vmName[2] == '1' && vmName[3] == '0')
		ipHolder[13] = '0';
	strcpy(ip, ipHolder);
}

UnixDomainSocket * unixDomainSocketMake(UnixDomainSocketType type, int shouldBind, char *init_sun_path) {
	UnixDomainSocket *unixSocket = malloc(sizeof(UnixDomainSocket));
	bzero(unixSocket, sizeof(UnixDomainSocket));

	struct sockaddr_un actualSocket; 
	bzero(&actualSocket, sizeof(actualSocket));
	char buff[MAXLINE];
	int fd = socket(AF_LOCAL, SOCK_STREAM, 0);
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
	actualSocket.sun_family = AF_LOCAL;
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

int acceptUnixDomainConnection(UnixDomainSocket * unixSocket) {
	struct sockaddr_un sock_addr;
	socklen_t len = sizeof(sock_addr);
	int ret = accept(unixSocket->fd, (struct sockaddr*)&sock_addr, &len);
	if(ret < 0) {
		printf("accept failed: %d\nTerminating...\n", errno);
		exit(1);
    }
    else
    	printf("accepted connection!\n");
    return ret; //fd
}

void printPacket(UnixDomainPacket *packet) {
	printf("Packet Info:\ndestIpAddress: %s\n", packet->destIpAddress);
	printf("sll_ifindex: %d\n", packet->hwAddr.sll_ifindex);
	printf("sll_hatype: %d\n", packet->hwAddr.sll_hatype);
	printf("sll_halen: %c\n", packet->hwAddr.sll_halen);
	printf("sll_addr: %s\n\n", packet->hwAddr.sll_addr);
}
