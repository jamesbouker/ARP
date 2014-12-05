#ifndef _JBOUKER_TOUR_
#define _JBOUKER_TOUR_

#include "unp.h"
#include "api.h"

#define TOUR_SIZE 			(sizeof(Tour) + 20)
#define TOUR_IP_ID			40132
#define MULTICAST_META_PORT	6345
#define MULTICAST_META_IP	"224.0.0.104"

typedef struct {
	char ipAddress[16];
	char vmName[5];
} TourStop;

//  * Had to remove linked list
//  passing it through packets would be much harder
//  removed all ptrs
typedef struct {
	TourStop stops[50];
	int size;
	int currentStop;
} Tour;

void 		addStopToTour(char *vmName);
void 		printTour();

//API functions
int 		areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, hwaddr *HWaddr);

#endif
