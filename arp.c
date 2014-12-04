#include "arp.h"
#include "api.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

Table table;
int pfSocketFD;
UnixDomainSocket *arpSocket;

//Table Shenanigans

TableInfo *insertIncompleteEntry(char *ipAddress, int if_index, unsigned short hatype, int clientFd) {
	TableInfo info;
	bzero(&info, sizeof(info));
	strcpy(info.ip_address, ipAddress);
	info.sll_ifindex = if_index;
	info.sll_hatype = hatype;
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
		if(info->hw_addr[i] == (char)'\0')
			return 0;
	}
	return 1;
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

void setup() {

	//setup the RAW PF_PACKET Socket
	pfSocketFD = socket(PF_PACKET, SOCK_RAW, htons(8976));
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

		struct timeval tv = {10, 0};
		printf("entering select\n");
		ret = select(max + 1, &set, NULL, NULL, &tv);
		
		if(ret > 0) {
			printf("select returned: %d\n", ret);
			if(FD_ISSET(arpSocket->fd, &set)) {
				
				//accept the connection!
				int fd = acceptUnixDomainConnection(arpSocket);

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
	            printf("Read from socket: %s\n", packet.destIpAddress);
	            printf("packet.hwAddr.sll_ifindex: %d\n", packet.hwAddr.sll_ifindex);

	            //if us or in our table respond right away
	            //else erase from table and send out broadcast on pf_packet
	            // put the ip and client FD in the table otherwise!

	            UnixDomainPacket returnPacket; bzero(&returnPacket, sizeof(returnPacket));

	            strcpy(returnPacket.destIpAddress, packet.destIpAddress);
				returnPacket.hwAddr.sll_ifindex = 1;
				returnPacket.hwAddr.sll_hatype = 1;
				returnPacket.hwAddr.sll_halen = 5;
				int i;
				for(i=0; i<6; i++)
					returnPacket.hwAddr.sll_addr[i] = 'c';

				ret = send(tempSocket.fd, &returnPacket, sizeof(returnPacket), 0);
				if(ret < 0)
					printf("send error: %d\n", errno);
				//close the connection!
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

	insertIncompleteEntry("127.0.0.1", 1, 1, 0);
	insertIncompleteEntry("255.255.255.255", 1, 1, 1);
	insertIncompleteEntry("122.0.123.238", 2, 1, 2);
	printTable();

	removeEntry("127.0.0.1");
	updateEntry("255.255.255.255", "abcdef");
	printTable();

	readSendLoop();

	exit(1);
}
