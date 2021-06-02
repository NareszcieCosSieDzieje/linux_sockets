/*
 * Compilation:  gcc -Wall ./tcp-client.c -o ./tcp-client
 * Usage:        ./tcp-client SERVER PORT RCVBUFFER_SIZE SNDBUFFER_SIZE
 *
 */

#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>


int getbuffsize(int sfd, int buffname) {
  int s;
  socklen_t slt = (socklen_t)sizeof(s);
  getsockopt(sfd, SOL_SOCKET, buffname, (void*)&s, &slt);
  return s;
}

void buffsizes(int sfd, int *srb, int *ssb) {
  *srb = getbuffsize(sfd, SO_RCVBUF);
  *ssb = getbuffsize(sfd, SO_SNDBUF);
}


int main(int argc, char** argv) {
  int sfd, rc, srb, ssb, s_srb, s_ssb;
  char buf[128];
  struct sockaddr_in saddr;
  struct hostent* addrent;

  addrent = gethostbyname(argv[1]);
  sfd = socket(PF_INET, SOCK_STREAM, 0);
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(argv[2]));
  memcpy(&saddr.sin_addr.s_addr, addrent->h_addr, addrent->h_length);
 
  srb = atoi(argv[3]);
  if (srb < 0) {
  	printf("TCP Recv buffer cannot be less than 0\n");
    exit(1);
  }
  ssb = atoi(argv[4]);
  if (srb < 0) {
  	printf("TCP Send buffer cannot be less than 0\n");
    exit(1);
  }
  setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &srb, sizeof(srb));
  setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &ssb, sizeof(ssb));
  connect(sfd, (struct sockaddr*) &saddr, sizeof(saddr));
  buffsizes(sfd, &s_srb, &s_ssb);
  printf("TCP:  RCVBUF = %6d [B]  SNDBUF = %6d [B]\n", s_srb, s_ssb);
  rc = read(sfd, buf, 128);
  write(1, buf, rc);
  close(sfd);
  return EXIT_SUCCESS;
}
