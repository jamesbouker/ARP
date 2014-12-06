#include "tour.h"
#include "api.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>


//TODO Clean these up - pulled from http://www.pdbuchan.com/rawsock/icmp4.c
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

//I can't get it to work with only one
int rtSendFD;
int rtReadFD;

int multicastFD;
struct sockaddr_in multicast_sock_addr;

int visitedByTour;
int heardMulticastBefore;

Tour tour;
char myIp[16];
char myVM[16];

char *myIpAddr() {
	bzero(myIp, sizeof(myIp));
	char vmName[16];
	gethostname(vmName, 16);
	ipForVm(vmName, myIp);
	return myIp;
}

char *myVMName() {
	bzero(myVM, sizeof(myVM));
	char vmName[16];
	gethostname(vmName, 16);
	strcpy(myVM, vmName);
	return myVM;
}

//Tour management
void addStopToTour(char *vmName) {
	char ip[16];
	ipForVm(vmName, ip);
	strcpy(tour.stops[tour.size].ipAddress, ip);
	strcpy(tour.stops[tour.size++].vmName, vmName); 
}

void printTour() {
	printf("Printing Tour\ncurrent stop: %d\nnumber of stops: %d\n", tour.currentStop, tour.size-1);
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
				UnixDomainPacket returnPacket; bzero(&returnPacket, sizeof(returnPacket));
				readFromUnixDomainSocket(arpSocket->fd, &returnPacket);
				printf("areq() returned with the hw_addr\n");
				printf("Ready to PING\n");
				return 1;
			}
		}
		else if(ret == 0) {
			printf("Timeout\n");
			return -1;
		}
		else {
			printf("select error\n");
			return -1;
		}
	}
}

void areqHelper(char *destIpAddress) {
	struct sockaddr_in sock_addr;
	hwaddr hw_addr;
	bzero(&hw_addr, sizeof(hw_addr));
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	inet_pton(AF_INET, destIpAddress, &sock_addr.sin_addr);
	areq((struct sockaddr*) &sock_addr, -1, &hw_addr);
}

// Checksum function - http://www.pdbuchan.com/rawsock/icmp4.c
uint16_t
checksum (uint16_t *addr, int len)
{
  int nleft = len;
  int sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (uint16_t);
  }

  if (nleft == 1) {
    *(uint8_t *) (&answer) = *(uint8_t *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}


//multicast
void initMulticastSocket() {
	if(visitedByTour == 0) {
		visitedByTour = 1;
		int ret;

		printf("Joining multicast: %s port: %d\n", MULTICAST_META_IP, MULTICAST_META_PORT);
		struct sockaddr_in sock_addr;
		bzero(&sock_addr, sizeof(sock_addr));

		sock_addr.sin_port = htons(MULTICAST_META_PORT);
		sock_addr.sin_family = AF_INET;
		ret = inet_pton(AF_INET, MULTICAST_META_IP, &(sock_addr.sin_addr));
		if(ret < 0) 
			printf("inet_pton error in multicast: %d\n", ret);

		socklen_t len = sizeof(sock_addr);
		ret = bind(multicastFD, (struct sockaddr *)&sock_addr, len);
		if(ret < 0) 
			printf("bind error in multicast: %d\n", ret);

		//from stevens
		Mcast_join(multicastFD, (struct sockaddr *)&sock_addr, len, NULL, 0);
		Mcast_set_loop(multicastFD, 0);

		multicast_sock_addr = sock_addr;
	}
}

//go to the next stop on tour
void goOnTour() {
	struct ip iphdr;
	struct sockaddr_in dest_addr;
	char packetData[TOUR_SIZE];
	char nextStop[16]; 
	char *tourPtr = (char*)&tour;
	char *ipPtr;
	int i;

	if (tour.currentStop < tour.size) {
		bzero(nextStop, sizeof(nextStop));
		bzero(&dest_addr, sizeof(dest_addr));

		strcpy(nextStop, tour.stops[tour.currentStop].ipAddress);
		dest_addr.sin_family = AF_INET;
  
  		//setup iphdr - http://www.pdbuchan.com/rawsock/icmp4.c
  			int ip_flags[4];
			// IPv4 header length (4 bits): Number of 32-bit words in header = 5
			iphdr.ip_hl = 5;
			// Internet Protocol version (4 bits): IPv4
			iphdr.ip_v = 4;
			// Type of service (8 bits)
			iphdr.ip_tos = 0;
			// Total length of datagram (16 bits): IP header + ICMP header + ICMP data
			// iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);
			iphdr.ip_len = htons (20 + sizeof(tour));
			// ID sequence number (16 bits): unused, since single datagram
			iphdr.ip_id = htons (TOUR_IP_ID);
			// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
			// Zero (1 bit)
			ip_flags[0] = 0;
			// Do not fragment flag (1 bit)
			ip_flags[1] = 0;
			// More fragments following flag (1 bit)
			ip_flags[2] = 0;
			// Fragmentation offset (13 bits)
			ip_flags[3] = 0;
			iphdr.ip_off = htons ((ip_flags[0] << 15)
			                  + (ip_flags[1] << 14)
			                  + (ip_flags[2] << 13)
			                  +  ip_flags[3]);
			// Time-to-Live (8 bits): default to maximum value
			iphdr.ip_ttl = 255;
			// Transport layer protocol (8 bits): 1 for ICMP
			iphdr.ip_p = PROTOCOL_NUM;
			inet_pton(AF_INET, myIpAddr(), &iphdr.ip_src);
			inet_pton(AF_INET, nextStop, &iphdr.ip_dst);
			// IPv4 header checksum (16 bits): set to 0 when calculating checksum
			iphdr.ip_sum = 0;
			iphdr.ip_sum = checksum ((uint16_t *) &iphdr, 20);
		//done setting up iphdr
		ipPtr = (char*)&iphdr;

		//copy that mess into the packet data for sending
		for(i=0; i<20; i++)
			packetData[i] = ipPtr[i];
		for(i=0; i<sizeof(tour); i++)
			packetData[i+20] = tourPtr[i];

		dest_addr.sin_addr.s_addr = iphdr.ip_dst.s_addr;
		int ret = sendto(rtSendFD, packetData, TOUR_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		if(ret > 0)
			printf("I am %s and I sent tour packet to next stop: %s\n\n", tour.stops[tour.currentStop-1].vmName, tour.stops[tour.currentStop].vmName);
		else
			printf("sendto failed...\n");
	}
	else {
		char buffer[100];
	    sprintf(buffer, "<<<<< This is node %s. Tour has ended. Group members please identify yourselves.>>>>>", tour.stops[tour.currentStop-1].vmName);
	   	heardMulticastBefore = 1;
	    printf("%s\n", buffer);
	    int ret = sendto(multicastFD, buffer, sizeof(buffer), 0, (struct sockaddr *)&multicast_sock_addr, sizeof(multicast_sock_addr));
	    if(ret > 0)
	    	printf("Node %s. Sending: %s\n", myVMName(), buffer);
	    else
	    	printf("multicast sendto() failed: %d\n", ret);
	}
}

//select - read - send
void readSendLoop() {
	fd_set set;
	int ret;
	int max;

	while(1) {
		max = max(rtReadFD, multicastFD);
		FD_ZERO(&set);
		FD_SET(rtReadFD, &set);
		FD_SET(multicastFD, &set);

		struct timeval tv = {5, 0};
		// printf("entering select\n");
		ret = select(max + 1, &set, NULL, NULL, &tv);
		
		if(ret > 0) {
			// printf("select returned: %d\n", ret);
			if(FD_ISSET(rtReadFD, &set)) {
				Tour *tourData;
				struct ip *iphdr;
				struct sockaddr_in from_addr;
				char packetData[TOUR_SIZE];
				socklen_t len = sizeof(struct sockaddr_in);

				recvfrom(rtReadFD, packetData, TOUR_SIZE, 0, (struct sockaddr *)&from_addr, &len);
				iphdr = (struct ip *)packetData;
				if(TOUR_IP_ID == ntohs(iphdr->ip_id)) {
					tourData = (Tour *)(packetData + 20);
					tour = tourData[0];
					TourStop lastStop = tour.stops[tour.currentStop-1];

					if(visitedByTour == 0) {
						areqHelper(lastStop.ipAddress);
						initMulticastSocket();
					}

					printf("\n<time> received source routing packet from %s\n", lastStop.vmName);
					tour.currentStop++;
					goOnTour();
				}
			}
			else if(FD_ISSET(multicastFD, &set)) {
				char buffer[MAXLINE]; 
				bzero(buffer, sizeof(buffer));
				int ret = recv(multicastFD, buffer, MAXLINE, 0);
				if(ret < 0) 
					printf("error in recv multicast: %d\n", ret);
				else {
					printf("\nNode %s. Received: %s\n", myVMName(), buffer);

					if(heardMulticastBefore == 0) {
						heardMulticastBefore = 1;
						sprintf(buffer, "<<<<< Node %s. I am a member of the group. >>>>>", myVMName());
						printf("Node %s. Sending: %s\n\n", myVMName(), buffer);
						ret = sendto(multicastFD, buffer, sizeof(buffer), 0, (struct sockaddr *)&multicast_sock_addr, sizeof(multicast_sock_addr));
						if(ret <= 0)
							printf("Error in sendto - sending multicast: %d\n", ret);
					}
					else {
						// printf("Already responded to multicast\n\n");
					}
				}
			}
		}
		else if(ret == 0) {
			if(heardMulticastBefore) {
				printf("\n5 Second Timeout occurred: I have sent my multicast\n");
				printf("Terminating Tour Application Gracefully\n\n");
				exit(1);
			}
		}
		else
			printf("error in select\n");
	}
}

//setup & main
void setup() {
	visitedByTour = 0;
	heardMulticastBefore = 0;

	int on = 1;
	int error = 0;
	int ret;
	
	//create sockets
	rtSendFD = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	rtReadFD = socket(AF_INET, SOCK_RAW, PROTOCOL_NUM);
	multicastFD = socket(AF_INET, SOCK_DGRAM, 0);

	//set IP_HDRINCL
	ret = setsockopt(rtReadFD, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if(ret < 0) error = ret;
	ret = setsockopt(rtSendFD, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if(ret < 0) error = ret;

	if(error != 0 || rtSendFD < 0 || rtReadFD < 0 || multicastFD < 0) {
		printf("Something went wrong in tour setup()\nTerminating...\n");
		exit(1);
	}
}

int main(int argc, char **argv) {
	setup();
	printf("Tour initiated\n");

	//extract the tour
	if(argc > 1) {
		char me[16];
		gethostname(me, 16);
		addStopToTour(me);
	}
	int i;
	for(i=1; i<argc; i++)
		addStopToTour(argv[i]);

	//either kick off tour or wait in select
	if(tour.size > 0) {
		tour.currentStop++;
		initMulticastSocket();
		printf("Kicking off tour\n");
		printTour();
		goOnTour();
	}
	else {
		printf("Waiting on messages\n");
	}

	readSendLoop();

	exit(1);
}