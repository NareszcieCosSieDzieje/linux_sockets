#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#define ETH_P_CUSTOM 0x8888

#define IRI_T_ADDRESS 0
#define IRI_T_ROUTE   1

struct ifrtinfo {
  int iri_type;
  char iri_iname[16];
  struct sockaddr_in iri_iaddr; /* IP address */
  struct sockaddr_in iri_rtdst; /* dst. IP address */
  struct sockaddr_in iri_rtmsk; /* dst. netmask */
  struct sockaddr_in iri_rtgip; /* gateway IP */
};

void print_ifrtinfo(struct ifrtinfo* data);
void handle_datagram(struct ifrtinfo* data);

int main(int argc, char** argv) {
  int sfd, i;
  ssize_t len;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  struct ifreq ifr;
  struct sockaddr_ll sall;

  sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
  ioctl(sfd, SIOCGIFINDEX, &ifr);
  memset(&sall, 0, sizeof(struct sockaddr_ll));
  sall.sll_family = AF_PACKET;
  sall.sll_protocol = htons(ETH_P_CUSTOM);
  sall.sll_ifindex = ifr.ifr_ifindex;
  sall.sll_hatype = ARPHRD_ETHER;
  sall.sll_pkttype = PACKET_HOST;
  sall.sll_halen = ETH_ALEN;
  bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));
  while(1) {
    frame = malloc(ETH_FRAME_LEN);
    memset(frame, 0, ETH_FRAME_LEN);
    fhead = (struct ethhdr*) frame;
    fdata = frame + ETH_HLEN;
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, NULL, NULL);
    // printf("GOT 1: %x\n", (unsigned short)sall.sll_protocol);
    // printf("GOT 2: %x\n", htons(ETH_P_CUSTOM));
    // if ( sall.sll_protocol != htons(ETH_P_CUSTOM) )
    //   continue;
    // }
    printf("Frame size: [%dB] | Source: %02x:%02x:%02x:%02x:%02x:%02x -> ", (int)len,
           fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
           fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
    printf("Dest: %02x:%02x:%02x:%02x:%02x:%02x | \n",
           fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
           fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);
    printf("Pkttype: 0x%04x\n", (unsigned short)fhead->h_proto); // sall.sll_pkttype
    printf("EtherType: 0x%04x\n", (unsigned short)sall.sll_protocol); // https://github.com/spotify/linux/blob/master/include/linux/if_ether.h -> ETH_P_ALL jako 0x0003
    struct ifrtinfo* read_info = (struct ifrtinfo*)fdata;
    print_ifrtinfo(read_info);
    handle_datagram(read_info);
    printf("\n\n");
    free(frame);
  }
  close(sfd);
  return EXIT_SUCCESS;
}


void print_ifrtinfo(struct ifrtinfo* data){
    char inet_buffer[4][INET_ADDRSTRLEN];
    
    const char *src_ip = inet_ntop(data->iri_iaddr.sin_family, &(data->iri_iaddr.sin_addr), inet_buffer[0], sizeof(inet_buffer[0]));
    const char *dst_ip = inet_ntop(data->iri_rtdst.sin_family, &(data->iri_rtdst.sin_addr), inet_buffer[1], sizeof(inet_buffer[1]));
    const char *dst_netmask = inet_ntop(data->iri_rtmsk.sin_family, &(data->iri_rtmsk.sin_addr), inet_buffer[2], sizeof(inet_buffer[2]));
    const char *gateway_ip = inet_ntop(data->iri_rtgip.sin_family, &(data->iri_rtgip.sin_addr), inet_buffer[3], sizeof(inet_buffer[3]));

    printf("-----------Ifrtinfo------------\n");
    printf("-Type: '%d'\n-Name: '%s'\n-Src_IP: '%s'\n-Dst_IP: '%s'\n-Dst_NETMASK: '%s'\n-Gateway_IP: '%s'\n", 
          data->iri_type,
          data->iri_iname,
          src_ip,
          dst_ip,
          dst_netmask,
          gateway_ip);
    printf("--------------------------------\n");
}

void handle_datagram(struct ifrtinfo* data){

  char inet_buffer[4][INET_ADDRSTRLEN];
    
  int iri_type = data->iri_type;
  const char* iri_name = data->iri_iname;
  const char *src_ip = inet_ntop(data->iri_iaddr.sin_family, &(data->iri_iaddr.sin_addr), inet_buffer[0], sizeof(inet_buffer[0]));
  const char *dst_ip = inet_ntop(data->iri_rtdst.sin_family, &(data->iri_rtdst.sin_addr), inet_buffer[1], sizeof(inet_buffer[1]));
  const char *dst_netmask = inet_ntop(data->iri_rtmsk.sin_family, &(data->iri_rtmsk.sin_addr), inet_buffer[2], sizeof(inet_buffer[2]));
  const char *gateway_ip = inet_ntop(data->iri_rtgip.sin_family, &(data->iri_rtgip.sin_addr), inet_buffer[3], sizeof(inet_buffer[3]));

  if (iri_type == IRI_T_ADDRESS) {  //TODO: OBSLUZ BLEDY
    printf("-------Set-Interface-IP--------\n");
    int sfd;
    struct ifreq ifr;
    struct sockaddr_in* sin;
    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, iri_name, strlen(iri_name) + 1);
    sin = (struct sockaddr_in*) &ifr.ifr_addr;
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = data->iri_iaddr.sin_addr.s_addr; // inet_addr(src_ip);
    ioctl(sfd, SIOCSIFADDR, &ifr);
    ioctl(sfd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    char fail = 0;
    if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0){
      printf("IOCTL ERR: %s\n", strerror(errno));
      fail = 1;
    }
    close(sfd);
    if (fail == 0){
      printf("Set %s's IP as %s\n", iri_name, src_ip);
    } else {
      printf("Failed to set IP (%s) for int (%s)\n", src_ip, iri_name);
    }
    printf("-------------------------------\n");
  } else if (iri_type == IRI_T_ROUTE){
    printf("---------Set-Gateway-IP--------\n");
    int sfd;
    struct rtentry route;
    struct sockaddr_in* addr;
    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    memset(&route, 0, sizeof(route));
    char ifname[] = "eth0";
    route.rt_dev = ifname;
    addr = (struct sockaddr_in*) &route.rt_gateway;
    addr->sin_family = AF_INET; //data->iri_rtgip.sin_family;
    addr->sin_addr.s_addr = inet_addr(gateway_ip); //data->iri_rtgip.sin_addr.s_addr;
    addr = (struct sockaddr_in*) &route.rt_dst;
    addr->sin_family = AF_INET; //data->iri_rtdst.sin_family;
    addr->sin_addr.s_addr = inet_addr(dst_ip); //data->iri_rtdst.sin_addr.s_addr;
    addr = (struct sockaddr_in*) &route.rt_genmask;
    addr->sin_family = AF_INET; //data->iri_rtmsk.sin_family;
    addr->sin_addr.s_addr = inet_addr(dst_netmask); //data->iri_rtmsk.sin_addr.s_addr;
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;
    char fail = 0;
    if (ioctl(sfd, SIOCADDRT, &route) < 0){
      printf("IOCTL ERR: %s\n", strerror(errno));
      fail = 1;
    }
    close(sfd);
    if (fail == 0){
      printf("Set gateway for IP %s\n", dst_ip);
      printf("Set the gateway's IP as %s\n", gateway_ip);
      printf("Set the gateway's IP mask as %s\n", dst_netmask);
    } else {
      printf("Failed to set the GW\n");
    }
    printf("-------------------------------\n");
  } else {
    printf("Unkown: iri_type (%d)\n", iri_type);
  }

}
