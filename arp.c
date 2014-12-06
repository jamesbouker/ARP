#include "arp.h"
#include "api.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#define PF_PACKET_RAW_PROTO	7936

Table table;
int pfSocketFD;
UnixDomainSocket *arpSocket;

//Table Shenanigans

TableInfo *insertIncompleteEntry(char *ipAddress, int if_index, int clientFd) {
	TableInfo info;
	bzero(&info, sizeof(info));
	strcpy(info.ip_address, ipAddress);
	info.sll_ifindex = if_index;
	info.client_fd = clientFd;

	table.entries[table.size++] = info;
	return &table.entries[table.size-1];
}

TableInfo *updateEntry(char *ipAddress, char *hw_addr) {
	TableInfo *info = entryForIp(ipAddress);
	if(info == NULL) {
		printf("Entry was NULL for: %s\n", ipAddress);
		return NULL;
	}

	int i;
	for(i=0; i<6; i++) 
		info->hw_addr[i] = hw_addr[i];
	return info;
}

TableInfo *entryForIp(char *ipAddress) {
	int i = indexForIp(ipAddress);
	if(i == -1) 
		return NULL;
	else
		return &table.entries[i];
}

void removeEntry(char *ipAddress) {
	int index = indexForIp(ipAddress);
	if(index >= 0) {
		table.entries[index] = table.entries[table.size-1];
		table.size = table.size - 1;
	}
}

int indexForIp(char *ipAddress) {
	int i;
	for(i=0; i<table.size; i++) {
		if(strcmp(table.entries[i].ip_address, ipAddress) == 0)
			return i;
	}
	return -1;
}

int isEntryValid(TableInfo *info) {
	int i;
	for(i=0; i<6; i++) {
		if(info->hw_addr[i] != (char)'\0')
			return 1;
	}
	return 0;
}

void printEntry(TableInfo *info) {
	if(info != NULL) {
		char *msg = isEntryValid(info)? "VALID" : "NOT VALID";
		printf("ip_address: %s hw_addr: %s sll_ifindex: %d client_fd: %d\n", info->ip_address, msg, info->sll_ifindex, info->client_fd);
	}
}

void printTable() {
	int i;
	printf("Printing ARP Table - Size: %d\n", table.size);
	for(i=0; i<table.size; i++)
		printEntry(&table.entries[i]);
	printf("\n");
}

//ARP Shenanigans

void broadcast(char *destIp) {
	char buffer[RAW_PACKET_SIZE];
	Interface eth0 = getEth0();
	// printInterface(eth0);

	struct sockaddr_ll sock_addr;
	bzero(&sock_addr,sizeof(sock_addr));
	sock_addr.sll_family = AF_PACKET;
	sock_addr.sll_protocol = htons(PF_PACKET_RAW_PROTO);
	sock_addr.sll_ifindex = eth0.if_index;
	sock_addr.sll_halen = 6;
	sock_addr.sll_hatype = 1;

	RawPacket rawPacket;
	int i;
	for(i=0; i<6; i++) {
		sock_addr.sll_addr[i] = 0xFF;
		rawPacket.destHWAddr[i] = 0xFF;
	}
	for(i=6; i<8; i++)
		sock_addr.sll_addr[i] = 0x00;
	for(i=0; i<6; i++) {
		rawPacket.sourceHWAddr[i] = eth0.hw_addr[i];
	}
	rawPacket.protocolNum = PF_PACKET_RAW_PROTO;

	UnixDomainPacket packet; 
	bzero(&packet, sizeof(packet));
	strcpy(packet.destIpAddress, destIp);
	packet.hwAddr.sll_ifindex = -1;
	char *packetPtr = (char*)&packet;
	char *rawPacketPtr = (char*)&rawPacket.unixPacket;

	for(i=0; i<sizeof(packet); i++)
		rawPacketPtr[i] = packetPtr[i];

	rawPacketBuffer(&rawPacket, buffer);
	int ret = sendto(pfSocketFD, buffer, RAW_PACKET_SIZE, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
	printf("sent broadcast, sendto() ret: %d\n\n", ret);
}

void setup() {
	bzero(&table, sizeof(table));

	//setup the RAW PF_PACKET Socket
	pfSocketFD = socket(PF_PACKET, SOCK_RAW, htons(PF_PACKET_RAW_PROTO));
	if(pfSocketFD < 0) {
		printf("Error creating ARP socket - Terminating...\n");
		exit(1);
	}

	//setup the UnixDomainSocket
	arpSocket = unixDomainSocketMake(UnixDomainSocketTypeARP, 1, UNIX_PATH_ARP);
	int ret = listen(arpSocket->fd, 0);
	if(ret < 0)
		printf("Error in listen: %d\n", ret);
	else
		printf("Listen succeeded: %d\n", ret);

	//setup the table
	bzero(&table, sizeof(table));
}

void readSendLoop() {
	fd_set set;
	int ret;
	int max;

	while(1) {
		max = max(pfSocketFD, arpSocket->fd);
		FD_ZERO(&set);
		FD_SET(arpSocket->fd, &set);
		FD_SET(pfSocketFD, &set);

		// struct timeval tv = {10, 0};
		printf("entering select\n");
		ret = select(max + 1, &set, NULL, NULL, NULL);
		
		if(ret > 0) {
			printf("select returned: %d\n", ret);
			if(FD_ISSET(pfSocketFD, &set)) {
				char buffer[RAW_PACKET_SIZE];

				UnixDomainPacket packet; 
				bzero(&packet, sizeof(packet));
				char *packetPtr = (char*)&packet;

				struct sockaddr_ll sock_addr;
				socklen_t len = sizeof(sock_addr);

				int ret = recvfrom(pfSocketFD, buffer, RAW_PACKET_SIZE, 0, (struct sockaddr*)&sock_addr , &len);
				printf("recvfrom returned: %d\n", ret);
				int i;
				for(i=0; i<sizeof(UnixDomainPacket); i++)
					packetPtr[i] = buffer[14 + i];

				Interface eth0 = getEth0();
				if(packet.hwAddr.sll_ifindex == -1) {
					printf("\nBroadcast heard for ip: %s\n", packet.destIpAddress);
					if(strcmp(eth0.ip_addr, packet.destIpAddress) == 0) {
						printf("Found me I will reply now!\n");
						packet.hwAddr.sll_ifindex = eth0.if_index;
						packet.hwAddr.sll_hatype = 1;
						packet.hwAddr.sll_halen = 6;
						for(i=0; i<6; i++)
							packet.hwAddr.sll_addr[i] = eth0.hw_addr[i];

						RawPacket rawPacket; 
						bzero(&rawPacket, sizeof(rawPacket));
						//get the source hw_addr and put in destination
						for(i=0; i<6; i++)
							rawPacket.destHWAddr[i] = buffer[i+6];
						//set the source to our eth0
						for(i=0; i<6; i++)
							rawPacket.sourceHWAddr[i] = eth0.hw_addr[i];
						rawPacket.protocolNum = PF_PACKET_RAW_PROTO;
						rawPacket.unixPacket = packet;
						rawPacketBuffer(&rawPacket, buffer);

						bzero(&sock_addr, sizeof(sock_addr));
						sock_addr.sll_family = AF_PACKET;
						sock_addr.sll_protocol = htons(PF_PACKET_RAW_PROTO);
						sock_addr.sll_ifindex = eth0.if_index;
						sock_addr.sll_halen = 6;
						sock_addr.sll_hatype = 1;
						for(i=0; i<6; i++)
							sock_addr.sll_addr[i] = packet.hwAddr.sll_addr[i];
						for(i=6; i<8; i++)
							sock_addr.sll_addr[i] = 0x00;

						ret = sendto(pfSocketFD, buffer, RAW_PACKET_SIZE, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
						printf("Sent reply, sendto() ret: %d\n", ret);
					}
				}
				else {
					printf("\nGot reply for: %s's hw_addr - replying to Tour!\n", packet.destIpAddress);
					TableInfo *info = entryForIp(packet.destIpAddress);
					updateEntry(packet.destIpAddress, (char*)packet.hwAddr.sll_addr);

					info->sll_ifindex = packet.hwAddr.sll_ifindex;
		            if(info != NULL && isEntryValid(info)) {
		            	UnixDomainPacket returnPacket; 
			            bzero(&returnPacket, sizeof(returnPacket));

			            strcpy(returnPacket.destIpAddress, packet.destIpAddress);
						returnPacket.hwAddr.sll_ifindex = info->sll_ifindex;
						returnPacket.hwAddr.sll_hatype = 1;
						returnPacket.hwAddr.sll_halen = 6;
						int i;
						for(i=0; i<6; i++)
							returnPacket.hwAddr.sll_addr[i] = info->hw_addr[i];

						ret = send(info->client_fd, &returnPacket, sizeof(returnPacket), 0);
						printf("sent packet to Tour send() returned: %d\n", ret);
						close(info->client_fd);
					}
					else
						printf("For some reason couldn't find info in table\n");
					printf("\n");
				}
			}
			else if(FD_ISSET(arpSocket->fd, &set)) {
				
				//accept the connection!
				int fd = acceptUnixDomainConnection(arpSocket);
				printf("\n");

				//make pretend unix socket
				UnixDomainSocket tempSocket;
				tempSocket.fd = fd;
				strcpy(tempSocket.sun_path, UNIX_PATH_ARP);

				//make the packet which will recive the message
	            UnixDomainPacket packet; 
	            bzero(&packet, sizeof(packet));

	            //read
	            readFromUnixDomainSocket(tempSocket.fd, &packet);

	            //handle read TODO
	            printf("Read from unix socket: %s\n", packet.destIpAddress);

	            //if in our table respond right away
	            //else send out broadcast on pf_packet
	            TableInfo *info = entryForIp(packet.destIpAddress);
	            if(info != NULL && isEntryValid(info)) {
	            	printf("%s existed in table, replying to Tour immidiately\n", packet.destIpAddress);

	            	UnixDomainPacket returnPacket; 
		            bzero(&returnPacket, sizeof(returnPacket));

		            strcpy(returnPacket.destIpAddress, packet.destIpAddress);
					returnPacket.hwAddr.sll_ifindex = info->sll_ifindex;
					returnPacket.hwAddr.sll_hatype = 1;
					returnPacket.hwAddr.sll_halen = 6;
					int i;
					for(i=0; i<6; i++)
						returnPacket.hwAddr.sll_addr[i] = info->hw_addr[i];

					ret = send(tempSocket.fd, &returnPacket, sizeof(returnPacket), 0);
					if(ret < 0)
						printf("send error: %d\n", errno);
					close(tempSocket.fd);
	            }
	            else {
	            	printf("Could not find in table, inserting incomplete entry and broadcasting\n");
	            	insertIncompleteEntry(packet.destIpAddress, -1, fd);
	            	broadcast(packet.destIpAddress);
	            }
			}
		}
		else if(ret == 0) {
			//timeout
			printf("Time out occurred\n");
		}
		else
			printf("Select error\n");
	}
}

int main(int argc, char **argv) {
	setup();
	readSendLoop();

	exit(1);
}
