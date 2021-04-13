#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

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

char* errbuf;
pcap_t* handle;
libnet_t *ln;
u_int32_t dstip;
char lastreplymac[ETH_ALEN];

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

void send_arp_request_unicast(bool is_ethernet, libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr, u_int8_t ethernet_dst_hw_addr);
 
void send_arp_request_broadcast(bool is_ethernet, libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr);

void recv_arp_reply(const char *unused, struct pcap_pkthdr *h, const char * const packet);

void recv_handler(void);

int main(int argc, char** argv) {
    
    atexit(cleanup);
    signal(SIGINT, stop);

    char* interface = NULL;
    char* target_ip = NULL;
    bool ethernet = true;
    int max_count = -1;

    if (argc < 3){
        perror("\n");
    }
    if (argc >= 3) { // INTERFACE IP
        *interface = argv[1];
        *target_ip = argv[2];
    }
    if (argc >= 4) { // INTERFACE IP ETHER/WIFI (0 == ethernet, > 0 == wifi)
        int ether_check = 0;
        if (str2int(&ether_check, argv[3], 10) == STR2INT_SUCCESS) {
            if (ether_check > 0){
                ethernet = false;
            }
        }
    }
    if (argc >= 5 ) { // INTERFACE IP ETHER/WIFI COUNT 
        if (str2int(&max_count, argv[4], 10) == STR2INT_SUCCESS) {
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
    pcap_set_promisc(handle, 1);
    pcap_set_snaplen(handle, 65535);
    pcap_activate(handle);
    pcap_lookupnet(argv[1], &netp, &maskp, errbuf);
    // FIXME! EXPRESSION setflter compile
    pcap_compile(handle, &fp, argv[2], 0, maskp);
    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_perror(handle, "pcap_setfilter()");
        exit(EXIT_FAILURE);
    }

    u_int32_t target_ip_addr, src_ip_addr;
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr* src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    ln = libnet_init(LIBNET_LINK, argv[1], errbuf);
    src_ip_addr = libnet_get_ipaddr4(ln);
    src_hw_addr = libnet_get_hwaddr(ln);
    target_ip_addr = libnet_name2addr4(ln, argv[2], LIBNET_RESOLVE);
    dstip = target_ip_addr; //TODO: necessary?

    bool first_iter = true;
    while(max_count != 0){

        if (first_iter){
            // stuff to do

            arp_request_broadcast(ethernet, ln, src_hw_addr->ether_addr_octet, (u_int8_t*) &src_ip_addr, zero_hw_addr, (u_int8_t*) &target_ip_addr); //TODO:

            // get reply
            // target hw_addr = ...
            first_iter = false;
        } else {
            arp_request_unicast();
        
        }

        
        pingmac_send(xrandom(), c);
        const uint32_t w = wait_time(deadline, packetwait);
        if (w == 0) {
                break;
        }
        ping_recv(pcap, w,  (pcap_handler)pingmac_recv);
                    usleep(1);

        if (max_count > 0){
            max_count--;
        }
     }

    return EXIT_SUCCESS;
    
    /*
     int ret;
                        if (0 > (ret = pcap_dispatch(pcap, -1,
                                                     func,
                                                     NULL))) {
                    // rest, so we don't take 100% CPU... mostly
                       
                    usleep(1);
    */


}


void stop(int signo) {
  exit(EXIT_SUCCESS);
}


void cleanup() {
    pcap_close(handle);
    free(errbuf);
    libnet_destroy(ln);
    //TODO:! Print stats arp packets
    // printf("%s: %d\n", packet_keys[i], packet_counters[i]);
}


void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct ether_header *eptr;
  eptr = (struct ether_header *) bytes;
  printf("[%dB of %dB]\n", h->caplen, h->len);
  if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
    packet_counters[0]++;


    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = bytes + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol == IPPROTO_TCP) {
      packet_counters[2]++;
    } else if (protocol == IPPROTO_UDP) {
      packet_counters[3]++;
    }
  } else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
    packet_counters[1]++;
  } else {
    packet_counters[4]++;
  }
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

void send_arp_request_unicast(bool is_ethernet, libnet_t *libnet, const uint8_t * sender_hw_addr, const uint8_t * sender_proto_addr, const uint8_t * target_hw_addr, uint8_t * target_proto_addr, u_int8_t ethernet_dst_hw_addr) {

    static unsigned int num_sent = 0;

    static libnet_ptag_t arp=0, eth=0;

    if (-1 == (arp = libnet_autobuild_arp(
        ARPOP_REQUEST,                     /* operation type       */
        sender_hw_addr,                    /* sender hardware addr */
        (u_int8_t*) &sender_proto_addr,    /* sender protocol addr */
        target_hw_addr,                    /* target hardware addr */
        (u_int8_t*) &target_proto_addr,    /* target protocol addr */
        libnet                             /* libnet context       */
        ))) {                   
        libnet_geterror(libnet));          
    };                               

    if (is_ethernet) {
        eth = libnet_build_ethernet(ethernet_dst_hw_addr,
                                srcmac,
                                ETHERTYPE_ARP,
                                NULL, // payload
                                0, // payload size
                                libnet,
                                eth);
        
    } else {
        int16_t vlan_prio = 1 // range of 0 - 7;
        eth = libnet_build_802_1q(ethernet_dst_hw_addr,
                              srcmac,
                              ETHERTYPE_VLAN,
                              vlan_prio,
                              0, // cfi
                              vlan_tag,
                              ETHERTYPE_ARP,
                              NULL, // payload
                              0, // payload size
                              libnet,
                              eth);
    }
    if (-1 == eth) {
        fprintf(stderr, "arping: %s: %s\n", (vlan_tag >= 0) ? "libnet_build_802_1q()" : "libnet_build_ethernet()",
        libnet_geterror(libnet));
    }
    if (-1 == libnet_write(libnet)) {
        fprintf(stderr, "arping: libnet_write(): %s\n",
        libnet_geterror(libnet));
    }
    numsent++;
 
    printf("Send %d messages\n", numsent);
    // libnet_autobuild_ethernet(
    //     bcast_hw_addr,                     /* ethernet destination */
    //     ETHERTYPE_ARP,                     /* ethertype            */
    //     ln);                               /* libnet context       */


    // libnet_write(ln);

    // const uint8_t padding[16] = {0};
 
    //  if (-1 == (arp = libnet_build_arp(
    //                    ARPHRD_ETHER,
    //                    ETHERTYPE_IP,
    //                    ETH_ALEN,
    //                    IP_ALEN,
    //                    send_reply ? ARPOP_REPLY : ARPOP_REQUEST,
    //                    srcmac,
    //                    (uint8_t*)&srcip,
    //                    unsolicited ? (uint8_t*)ethxmas : (uint8_t*)ethnull,
    //                    (uint8_t*)&dstip,
    //                    (uint8_t*)padding,
    //                    sizeof padding,
    //                    libnet,
    //                    arp))) {
    //      fprintf(stderr, "arping: libnet_build_arp(): %s\n",
    //          libnet_geterror(libnet));
    //      sigint(0);
    //  }

 }

 
void send_arp_request_broadcast(bool is_ethernet, libnet_t *libnet, sender_hw_addr, sender_proto_addr, target_hw_addr, target_proto_addr) {
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    send_arp_request_unicast(is_ethernet, libnet, sender_hw_addr, sender_proto_addr, target_hw_addr, target_proto_addr, bcast_hw_addr);
}


void recv_arp_reply(const char *user, struct pcap_pkthdr *h, const char * const packet) {

    const unsigned char *pkt_srcmac;
    const struct libnet_802_1q_hdr *veth;
    struct libnet_802_3_hdr *heth;
    struct libnet_arp_hdr *harp;
 
    //FIXME:!
    int vlan_tag = -1;
    if (vlan_tag >= 0) {  //FIXME:!
        veth = (void*)packet;
        harp = (void*)((char*)veth + LIBNET_802_1Q_H);
        pkt_srcmac = veth->vlan_shost;
    } else {
        // Short packet.
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
     }
 
    // ARP reply.
    if (htons(harp->ar_op) != ARPOP_REPLY) {
            return;
    }

    // From IPv4 address reply.
    if (htons(harp->ar_pro) != ETHERTYPE_IP) {
            return;
    }

    printf("Arping: ARP reply ... from IPv4 address\n");

    // To Ethernet address.
    if (htons(harp->ar_hrd) != ARPHRD_ETHER) {
            return;
    }
    if (verbose > 3) {
            printf("arping: ... to Ethernet address\n");
    }

    // Must be sent from target address.
    // Should very likely only be used if using -T.
    if (addr_must_be_same) {
            if (memcmp((u_char*)harp + sizeof(struct libnet_arp_hdr),
                    dstmac, ETH_ALEN)) {
                    return;
            }
    }
    if (verbose > 3) {
            printf("arping: ... sent by acceptable host\n");
    }

    // // Special case: If we're not in promisc mode we could still
    // // get packets where DST mac is not us, if they're *sent* from
    // // the local host. This is an edge case but in general falls under "is promisc?".
    // //
    // // It may cause confusion because `-p` now means not just
    // // enable promisc mode (disable filter on card / in kernel),
    // // but also allow packets to any destination (disable filter
    // // in `arping`).
    // {
    //         const uint8_t* p = (u_char*)harp
    //                 + sizeof(struct libnet_arp_hdr)
    //                 + ETH_ALEN
    //                 + IP_ALEN;
    //         char buf[128];
    //         if (!promisc && memcmp(p, srcmac, ETH_ALEN)) {
    //                 format_mac(p, buf, sizeof buf);
    //                 if (verbose > 3) {
    //                         printf("arping: ... but sent from %s\n", buf);
    //                 }
    //                 return;
    //         }
    // }
    // if (verbose > 3) {
    //         printf("arping: ... destination is the source we used\n");
    // }

    char buf[128];

    // Actually the IPv4 address we asked for.
    uint32_t ip;
    memcpy(&ip, (char*)harp + harp->ar_hln + LIBNET_ARP_H, 4);
    if (dstip != ip) {
        printf("arping: from IPv4 address!\n");
        return;
    }

    printf("arping: for the right IPv4 address!\n");

    numrecvd++;

    printf("%d bytes from %s (%s): index=%d", h->len, format_mac(pkt_srcmac, buf, sizeof(buf)), libnet_addr2name4(ip, 0), numrecvd);

    // fflush(stdout);

    memcpy(lastreplymac, pkt_srcmac, ETH_ALEN);

 }

  void recv_handler() {
    int fd;
    fd = pcap_get_selectable_fd(pcap);
    if (fd == -1) {
        fprintf(stderr, "arping: pcap_get_selectable_fd()=-1: %s\n",
        pcap_geterr(pcap));
        exit(1);
    }

    char done = 0;

    while (!done) {

        int fd_set fds;
        int r;

        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        r = select(fd + 1, &fds, NULL, NULL, &tv);

        if (r == 0) {
            printf("Timeout\n");
            // fflush(stdout);
            done = 1;
        }
        else if (r == -1){
            if (errno != EINTR) {
                done = 1;
                fprintf(stderr, "arping: select() failed: %s\n", strerror(errno));
            }
        } else {
            int ret;
            if (0 > (ret = pcap_dispatch(pcap, -1, recv_arp_reply, NULL))) {
                usleep(1);
            }
        }
    }
 }

