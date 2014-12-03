#ifndef _JBOUKER_API_
#define _JBOUKER_API_

#include "unp.h"

#define UNIX_PATH_ARP 	"/tmp/cse533-1895"

typedef struct {
	int             sll_ifindex;	 	/* Interface number */
	unsigned short  sll_hatype;	 		/* Hardware type */
	unsigned char   sll_halen;		 	/* Length of address */
	unsigned char   sll_addr[8];	 	/* Physical layer address */
} hwaddr;

typedef struct {
	hwaddr hwAddr;
	char destIpAddress[16];
} UnixDomainPacket;

typedef enum {
	UnixDomainSocketTypeTour = 0,
	UnixDomainSocketTypeARP
} UnixDomainSocketType;

typedef struct {
  	char sun_path[MAXLINE];
  	UnixDomainSocketType type;
  	int fd;
} UnixDomainSocket;

//Unix Domain functions
UnixDomainSocket   *unixDomainSocketMake(UnixDomainSocketType type, int shouldBind, char *init_sun_path);
void 				unixDomainSocketUnlink(UnixDomainSocket * unixSocket);
int 				readFromUnixDomainSocket(int fd, UnixDomainPacket *packet);

void				acceptUnixDomainConnection(UnixDomainSocket * unixSocket);




//unused as of yet
// int 		createARPUnixDomainSocket();		//used by client
// int 		createUnixDomainSocketToTour();	//used by areq API

// void 		sendToARPUnixDomain(int fd, UnixDomainPacket *packet); 		//used in areq
// void 		readFromARPUnixDomain();	//used in areq
// void		readFromTour();				//ARP uses to read from the unix domain
// void 		sendToTour();				//ARP sends to Tour unix domain

#endif
