#ifndef _JBOUKER_TOUR_
#define _JBOUKER_TOUR_

#include "unp.h"
#include "api.h"

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
