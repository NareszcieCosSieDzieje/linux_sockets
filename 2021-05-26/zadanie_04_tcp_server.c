/*
 *
 * Compilation:  gcc -Wall ./tcp-server.c -o ./tcp-server
 * Usage:        ./tcp-server RCVBUF_SIZE SNDBUF_SIZE
 *
 */

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
  socklen_t sl;
  int sfd, cfd, on = 1;
  struct sockaddr_in saddr, caddr;
  int srb, ssb, s_srb, s_ssb;

  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(1234);
  sfd = socket(PF_INET, SOCK_STREAM, 0);
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*) &on, sizeof(on));
  bind(sfd, (struct sockaddr*) &saddr, sizeof(saddr));
  srb = atoi(argv[1]);
  if (srb < 0) {
  	printf("TCP Recv buffer cannot be less than 0\n");
    exit(1);
  }
  ssb = atoi(argv[2]);
  if (srb < 0) {
  	printf("TCP Send buffer cannot be less than 0\n");
    exit(1);
  }
  setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &srb, sizeof(srb));
  setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &ssb, sizeof(ssb));
  buffsizes(sfd, &s_srb, &s_ssb);
  printf("TCP:  RCVBUF = %6d [B]  SNDBUF = %6d [B]\n", s_srb, s_ssb);
  listen(sfd, 5);
  while(1) {
    memset(&caddr, 0, sizeof(caddr));
    sl = sizeof(caddr);
    cfd = accept(sfd, (struct sockaddr*) &caddr, &sl);
    write(cfd, "Hello World!\n", 14);
    //sleep(1200);
    close(cfd);
  }
  close(sfd);
  return EXIT_SUCCESS;
}
