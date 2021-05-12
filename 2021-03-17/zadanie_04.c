#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ETH_P_CUSTOM 0x8888

int main(int argc, char** argv) {
    if (argc < 3){
        printf("Arg1 - interface name, arg2 dest mac address\n");
        exit(-1);
    }

    int sfd, i, ifindex;
    ssize_t len;
    char* frame;
    char* fdata;
    struct ethhdr* fhead;
    struct ifreq ifr, ifr2;
    struct sockaddr_ll sall, dall;

    sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
    ioctl(sfd, SIOCGIFINDEX, &ifr);
    memset(&sall, 0, sizeof(struct sockaddr_ll));
    sall.sll_family = AF_PACKET;
    sall.sll_protocol = htons(ETH_P_ALL);
    sall.sll_ifindex = ifr.ifr_ifindex;
    sall.sll_hatype = ARPHRD_ETHER;
    sall.sll_pkttype = PACKET_HOST;
    sall.sll_halen = ETH_ALEN;

    strncpy(ifr2.ifr_name, argv[1], IFNAMSIZ);
    ioctl(sfd, SIOCGIFINDEX, &ifr2);
    ifindex = ifr2.ifr_ifindex;
    ioctl(sfd, SIOCGIFHWADDR, &ifr2);
    memset(&dall, 0, sizeof(struct sockaddr_ll));
    dall.sll_family = AF_PACKET;
    dall.sll_protocol = htons(ETH_P_CUSTOM);
    dall.sll_ifindex = ifindex;
    dall.sll_hatype = ARPHRD_ETHER;
    dall.sll_pkttype = PACKET_OUTGOING;
    dall.sll_halen = ETH_ALEN;
    sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &dall.sll_addr[0], &dall.sll_addr[1], &dall.sll_addr[2],
            &dall.sll_addr[3], &dall.sll_addr[4], &dall.sll_addr[5]);

    bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));
    while(1) {
        frame = malloc(ETH_FRAME_LEN);
        memset(frame, 0, ETH_FRAME_LEN);
        fhead = (struct ethhdr*) frame;
        fdata = frame + ETH_HLEN;
        len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, NULL, NULL);

         printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int)len,
                fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
                fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
        printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
                fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
                fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);
        printf("%s\n", fdata);
        for (i = 0; i < len ; i++) {
            printf("%02x ", (unsigned char) frame[i]);
            if ((i + 1) % 16 == 0)
            printf("\n");
        }
        printf("\n\n");
        memcpy(fhead->h_dest, &dall.sll_addr, ETH_ALEN);
        fhead->h_proto = htons(ETH_P_CUSTOM);
        sendto(sfd, frame, strlen(fdata), 0,
                (struct sockaddr*) &dall, sizeof(struct sockaddr_ll));

        free(frame);
    }
    close(sfd);
    return EXIT_SUCCESS;
}
