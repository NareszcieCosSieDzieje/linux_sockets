#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <pcap.h>
#include <libnet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

char* errbuf;
pcap_t* handle;
libnet_t *ln;
uint32_t dstip;
u_int8_t lastreplymac[ETH_ALEN];
char glob_done = 0;


unsigned int numsent = 0;       
unsigned int numrecvd = 0;

typedef enum {
    STR2INT_SUCCESS,
    STR2INT_OVERFLOW,
    STR2INT_UNDERFLOW,
    STR2INT_INCONVERTIBLE
} str2int_errno;

void stop(int signo);

void cleanup(void);

str2int_errno str2int(int *out, char *s, int base);

char* format_mac(const unsigned char* mac, char* buf, size_t bufsize) {
    snprintf(buf, bufsize, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}
   

void send_arp_request_unicast(libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr, const uint8_t * ethernet_dst_hw_addr);
 
void send_arp_request_broadcast(libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr);

void recv_arp_reply(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet);

void recv_handler(void);

int main(int argc, char** argv) {
    
    atexit(cleanup);
    signal(SIGINT, stop);

    // char* interface = NULL;
    // char* target_ip = NULL;
    int max_count = -1;

    if (argc < 3){
        perror("\n");
    }
    if (argc >= 3) { // INTERFACE IP
        // strcpy(interface, argv[1]);
        // strcpy(target_ip, argv[2]);
    }
    if (argc >= 4) { // INTERFACE IP COUNT 
        if (str2int(&max_count, argv[3], 10) == STR2INT_SUCCESS) {
            if (max_count <= 0){
                max_count = -1;
            }
        }
    }
    
    bpf_u_int32 netp, maskp;
    struct bpf_program fp;

    errbuf = malloc(PCAP_ERRBUF_SIZE);
    handle = pcap_create(argv[1], errbuf);
    if (pcap_setnonblock(handle, 1, errbuf)) {
        fprintf(stderr, "arping: pcap_set_nonblock(): %s\n", errbuf);
        exit(1);
    }
    // if (0 != pcap_set_immediate_mode(handle, 1)){
    //     perror("Could not set immediate mode for pcap\n");
    // }
    if (0 != pcap_set_timeout(handle, 100)){
        perror("Could not set timeout for pcap handle\n");
    }
    pcap_set_promisc(handle, 1);
    pcap_set_snaplen(handle, 65535);
    pcap_activate(handle);
    pcap_lookupnet(argv[1], &netp, &maskp, errbuf);

    pcap_compile(handle, &fp, "arp[6:2]=2", 0, maskp); // ADDED ARP REPLY FILTER
    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_perror(handle, "pcap_setfilter()");
        exit(EXIT_FAILURE);
    }

    u_int32_t target_ip_addr, src_ip_addr;
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr* src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    if (NULL == (ln = libnet_init(LIBNET_LINK, argv[1], errbuf))){
        perror("Libnet init error\n");
        exit(1);
    }
    src_ip_addr = libnet_get_ipaddr4(ln);
    src_hw_addr = libnet_get_hwaddr(ln);
    target_ip_addr = libnet_name2addr4(ln, argv[2], LIBNET_RESOLVE);
    dstip = target_ip_addr; //TODO: necessary?

    char first_iter = 1;
    while(max_count != 0){
        
        // send_arp_request_unicast(ln, (const u_int8_t *) &(src_hw_addr->ether_addr_octet), (const u_int8_t*) &src_ip_addr, (const u_int8_t *) &zero_hw_addr, (u_int8_t*) &target_ip_addr, (const u_int8_t*) &bcast_hw_addr);

        if (first_iter){
            send_arp_request_broadcast(ln, (const u_int8_t *) &(src_hw_addr->ether_addr_octet), (const u_int8_t*) &src_ip_addr, (const u_int8_t *) &zero_hw_addr, (u_int8_t*) &target_ip_addr);
            first_iter = 0;
        } else {
            send_arp_request_unicast(ln, (const u_int8_t *) &(src_hw_addr->ether_addr_octet), (const u_int8_t*) &src_ip_addr, (const u_int8_t *) &zero_hw_addr, (u_int8_t*) &target_ip_addr, (const u_int8_t*) &lastreplymac);
        }
        recv_handler();
        
        if (max_count > 0){
            max_count--;
        }
     }
    return EXIT_SUCCESS;
}


void stop(int signo) {
  exit(EXIT_SUCCESS);
}


void cleanup() {
    pcap_close(handle);
    free(errbuf);
    libnet_destroy(ln);
    int num = 0;
    if (numsent !=0 ) {
        num = (100*(numsent-numrecvd)/numsent);
    } 
    printf("\nSent: (%d).\nReceived: (%d).\nLoss: (%d).\n", numsent, numrecvd, num);
}


str2int_errno str2int(int *out, char *s, int base) {
    char *end;
    if (s[0] == '\0' || isspace(s[0]))
        return STR2INT_INCONVERTIBLE;
    errno = 0;
    long l = strtol(s, &end, base);
    if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX))
        return STR2INT_OVERFLOW;
    if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN))
        return STR2INT_UNDERFLOW;
    if (*end != '\0')
        return STR2INT_INCONVERTIBLE;
    *out = l;
    return STR2INT_SUCCESS;
}

void send_arp_request_unicast(libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr, const u_int8_t* ethernet_dst_hw_addr) {

    static libnet_ptag_t arp=0, eth=0;

    const uint8_t padding[16] = {0};        

    if (-1 == (arp = libnet_build_arp(ARPHRD_ETHER,
                            ETHERTYPE_IP,
                            ETH_ALEN,
                            IP_ALEN,
                            ARPOP_REQUEST,
                            sender_hw_addr,
                            sender_proto_addr,
                            target_hw_addr,
                            target_proto_addr,
                            (uint8_t*)padding,
                            sizeof padding,
                            libnet,
                            arp))) 
    // if (-1 == (arp = libnet_autobuild_arp(
    //     ARPOP_REQUEST,                     /* operation type       */
    //     sender_hw_addr,                    /* sender hardware addr */
    //     sender_proto_addr,                 /* sender protocol addr */
    //     target_hw_addr,                    /* target hardware addr */
    //     target_proto_addr,                 /* target protocol addr */
    //     libnet                             /* libnet context       */
    //     ))) 
    {                   
        libnet_geterror(libnet);          
        perror("Libnet fail autobuild.\n");
    };                               
    eth = libnet_build_ethernet(ethernet_dst_hw_addr,
                                sender_hw_addr,
                                ETHERTYPE_ARP,
                                NULL, // payload
                                0, // payload size
                                libnet,
                                eth);
        
    if (-1 == eth) {
        libnet_geterror(libnet);
        perror("Libnet fail autobuild ether.\n");
    }
    if (-1 == libnet_write(libnet)) {
        fprintf(stderr, "arping: libnet_write(): %s\n",
        libnet_geterror(libnet));
    }
    numsent++;
 
    printf("Sent %d messages\n", numsent);
 }

void send_arp_request_broadcast(libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr) {
    const uint8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    send_arp_request_unicast(libnet, sender_hw_addr, sender_proto_addr, target_hw_addr, target_proto_addr, (const uint8_t*) &bcast_hw_addr);
}


void recv_arp_reply(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet) {

    const unsigned char *pkt_srcmac;
    struct libnet_802_3_hdr *heth;
    struct libnet_arp_hdr *harp;
 
    if (h->caplen < LIBNET_ETH_H + LIBNET_ARP_H + 2*(ETH_ALEN + 4)) {
        return;
    }

    heth = (void*)packet;
    harp = (void*)((char*)heth + LIBNET_ETH_H);
    pkt_srcmac = heth->_802_3_shost;
    // Wrong length of hardware address.
    if (harp->ar_hln != ETH_ALEN) {
        return;
    }

    // Wrong length of protocol address.
    if (harp->ar_pln != 4) {
        return;
    }
 
    // ARP reply.
    if (htons(harp->ar_op) != ARPOP_REPLY) {
        return;
    }

    // From IPv4 address reply.
    if (htons(harp->ar_pro) != ETHERTYPE_IP) {
        return;
    }

    // To Ethernet address.
    if (htons(harp->ar_hrd) != ARPHRD_ETHER) {
            return;
    }

    char buf[128];

    // Check if IPv4 addresses match (desired ping vs reply).
    uint32_t ip;
    memcpy(&ip, (char*)harp + harp->ar_hln + LIBNET_ARP_H, 4);
    if (dstip != ip) {
        printf("Arping from (%s)\n", libnet_addr2name4(ip, 0));
        return;
    }

    glob_done = 1;

    numrecvd++;

    printf("%d bytes from %s (%s): index=%d\n", h->len, format_mac(pkt_srcmac, buf, sizeof(buf)), libnet_addr2name4(ip, 0), numrecvd);

    memcpy(lastreplymac, pkt_srcmac, ETH_ALEN);
 }

  void recv_handler() {

    int fd;
    fd = pcap_get_selectable_fd(handle);
    if (fd == -1) {
        fprintf(stderr, "arping: pcap_get_selectable_fd()=-1: %s\n",
        pcap_geterr(handle));
        exit(1);
    }

    glob_done = 0;

    while (!glob_done) {

        fd_set fds;
        int r;

        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        r = select(fd + 1, &fds, NULL, NULL, &tv);

        if (r == 0) {
            printf("Timeout\n");
            fflush(stdout);
            glob_done = 1;
        }
        else if (r == -1){
            if (errno != EINTR) {
                glob_done = 1;
                fprintf(stderr, "arping: select() failed: %s\n", strerror(errno));
            }
        } else {
            int ret;
            if (0 > (ret = pcap_dispatch(handle, -1, (pcap_handler) recv_arp_reply, NULL))) {
                usleep(1);
            }
        }
    }
    glob_done = 0;
 }

