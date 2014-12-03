#ifndef _JBOUKER_ARP_
#define _JBOUKER_ARP_

#include "unp.h"

//I hate underscores - but for the sake of conformity
typedef struct {
	char ip_address[16];
	char hw_addr[6];
	int sll_ifindex;
	unsigned short sll_hatype;
	int client_fd;
} TableInfo;

typedef struct {
	TableInfo entries[100];
	int size;
} Table;

//Table functions
TableInfo 	*insertIncompleteEntry(char *ipAddress, int if_index, unsigned short hatype, int clientFd);
TableInfo 	*updateEntry(char *ipAddress, char *hw_addr);
TableInfo 	*entryForIp(char *ipAddress);
void 		removeEntry(char *ipAddress);
void 		printEntry(TableInfo *info);
void 		printTable();
int 		indexForIp(char *ipAddress);
int 		isEntryValid(TableInfo *info);

#endif
