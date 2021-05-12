/*
 * Copyright (C) 2021 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./pcapfilter.c -o ./pcapfilter -lpcap
 * Usage:        ./pcapfilter INTERFACE EXPRESSION
 * NOTE:         This program requires root privileges.
 *
 * Bug reports:  https://gitlab.cs.put.poznan.pl/mkalewski/ps-2021/issues
 *
 */

#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

char* errbuf;
pcap_t* handle;
int packet_counters[] = {0, 0, 0, 0, 0};
const char* packet_keys[] = {"IP", "ARP", "TCP", "UDP", "OTHER"};

void cleanup() {
  pcap_close(handle);
  free(errbuf);
  printf("\nStats:\n");
  for(int i=0; i<5; i++){
    printf("%s: %d\n", packet_keys[i], packet_counters[i]);
  }
}

void stop(int signo) {
  exit(EXIT_SUCCESS);
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

int main(int argc, char** argv) {
  bpf_u_int32 netp, maskp;
  struct bpf_program fp;

  atexit(cleanup);
  signal(SIGINT, stop);
  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(argv[1], errbuf);
  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_activate(handle);
  pcap_lookupnet(argv[1], &netp, &maskp, errbuf);
  pcap_compile(handle, &fp, argv[2], 0, maskp);
  if (pcap_setfilter(handle, &fp) < 0) {
    pcap_perror(handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }
  pcap_loop(handle, -1, trap, NULL);
}
