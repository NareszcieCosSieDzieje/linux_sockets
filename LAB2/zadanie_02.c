/*
 * Copyright (C) 2021 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./ifinfo.c -o ./ifinfo
 * Usage:        ./ifinfo
 *
 * Bug reports:  https://gitlab.cs.put.poznan.pl/mkalewski/ps-2021/issues
 *
 */

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct ifconf getifreqs(int sfd) {
  int len, lastlen;
  char* buf;
  struct ifconf ifc;

  lastlen = 0;
  len = 100 * sizeof(struct ifreq);
  while(1) {
    buf = malloc(len);
    memset(buf, 0, len);
    ifc.ifc_len = len;
    ifc.ifc_buf = buf;
    ioctl(sfd, SIOCGIFCONF, &ifc);
    if (ifc.ifc_len == lastlen)
      break;
    lastlen = ifc.ifc_len;
    len += 10 * sizeof(struct ifreq);  
    free(buf);
  }
  return ifc;
}

void ifsinfo(int sfd, struct ifconf ifc) {
  char* ptr;
  struct ifreq* ifr;
  struct sockaddr_in* addr_in;

  ptr = ifc.ifc_buf;
  while(ptr < ifc.ifc_buf + ifc.ifc_len) {
    ifr = (struct ifreq*) ptr;
    ptr += sizeof(struct ifreq);
    printf("%s\t", ifr->ifr_name);
    addr_in = (struct sockaddr_in*) &ifr->ifr_addr;
    printf("inet_addr:%s\t",
           inet_ntoa((struct in_addr)addr_in->sin_addr));

    struct ifreq buffer;
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, ifr->ifr_name);
    ioctl(sfd, SIOCGIFHWADDR, &buffer);
    printf("MAC:");
    for(int i = 0; i < 6; i++ )
	  {
	  	printf("%.2X", (unsigned char)buffer.ifr_hwaddr.sa_data[i]);
  	  if (i < 5) { 
        printf("-");
      }
    }
    printf("\n");
  }
}

int main(int argc, char** argv) {
  int sfd = socket(PF_INET, SOCK_DGRAM, 0);
  struct ifconf ifc = getifreqs(sfd);
  ifsinfo(sfd, ifc);
  free(ifc.ifc_buf);
  close(sfd);
  return 0;
}
