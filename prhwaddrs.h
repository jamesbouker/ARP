#ifndef _WHY_NO_HEADER_
#define _WHY_NO_HEADER_
#define _SO_MUCH_TIME_WASTED_FOR_NO_REASON_

#include "unp.h"
#include <stdio.h>
#include <sys/socket.h>

#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

struct hwa_info {
  char    if_name[IF_NAME];	/* interface name, null terminated */
  char    if_haddr[IF_HADDR];	/* hardware address */
  int     if_index;		/* interface index */
  short   ip_alias;		/* 1 if hwa_addr is an alias IP address */
  struct  sockaddr  *ip_addr;	/* IP address */
  struct  hwa_info  *hwa_next;	/* next of these structures */
};

typedef struct hwa_info hwa_info;

/* function prototypes */
hwa_info	*get_hw_addrs();
hwa_info	*Get_hw_addrs();
void free_hwa_info(hwa_info *);

#endif
