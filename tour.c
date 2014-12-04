#include "tour.h"
#include "api.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

//I can't get it to work with only one
int rtSendFD;
int rtReadFD;
Tour tour;

//Tour management
void addStopToTour(char *vmName) {
	char ip[16];
	ipForVm(vmName, ip);
	strcpy(tour.stops[tour.size].ipAddress, ip);
	strcpy(tour.stops[tour.size++].vmName, vmName);
}

void printTour() {
	printf("Printing Tour\nremaining stops: %d\n", tour.size-1);
	int i;
	for(i=0; i<tour.size; i++)
		printf("%s ", tour.stops[i].vmName);
	printf("\n\n");
}


//API
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


// setup() & main()
void setup() {
	bzero(&tour, sizeof(tour));
	
	int on = 1;
	int error = 0;
	int ret;
	
	//create sockets
	rtSendFD = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	rtReadFD = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
	
	//set IP_HDRINCL
	ret = setsockopt(rtReadFD, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if(ret < 0) error = ret;
	ret = setsockopt(rtSendFD, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if(ret < 0) error = ret;

	if(error != 0 || rtSendFD < 0 || rtReadFD < 0) {
		printf("Something went wrong in tour setup()\nTerminating...\n");
		exit(1);
	}
}

void areqHelper() {
	struct sockaddr_in sock_addr;
	hwaddr hw_addr;
	bzero(&hw_addr, sizeof(hw_addr));
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &sock_addr.sin_addr);
	areq((struct sockaddr*) &sock_addr, -1, &hw_addr);
}

int main(int argc, char **argv) {
	setup();

	//extract the tour
	if(argc > 1) {
		char me[16];
		gethostname(me, 16);
		addStopToTour(me);
	}
	int i;
	for(i=1; i<argc; i++) {
		addStopToTour(argv[i]);
	}

	//either kick off tour or wait in select
	if(tour.size > 0) {
		printTour();
	}
	else {

	}

	exit(1);
}
