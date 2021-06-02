/*
 * Copyright (C) 2021 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./06-read-aio.c -o ./06-read-aio -lrt
 * Usage:        ./06-read-aio SERVER PORT
 *
 * Bug reports:  https://gitlab.cs.put.poznan.pl/mkalewski/ps-2021/issues
 *
 */

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int rc = -1;

void callback(int sig) { 
	printf("Callback invoked!\n");
	rc = 1; 
}


int main(int argc, char** argv) {
  int sfd;
  char buf[128];
  struct sockaddr_in saddr;
  struct hostent *addrent;
  struct aiocb aio;

  addrent = gethostbyname(argv[1]);
  sfd = socket(PF_INET, SOCK_STREAM, 0);
  memset(&aio, 0, sizeof(aio));
  aio.aio_fildes = sfd;
  aio.aio_offset = 0;
  aio.aio_buf = buf;
  aio.aio_nbytes = 128;
  aio.aio_reqprio = 0;
  //aio.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
  aio.aio_sigevent.sigev_notify = SIGEV_THREAD;
  aio.aio_sigevent.sigev_notify_function = (void*)callback;
  aio.aio_sigevent.sigev_signo = SIGUSR1;
  aio.aio_lio_opcode = LIO_READ;
  signal(SIGUSR1, callback);
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(argv[2]));
  memcpy(&saddr.sin_addr.s_addr, addrent->h_addr, addrent->h_length);
  connect(sfd, (struct sockaddr*) &saddr, sizeof(saddr));
  aio_read(&aio);
  while (rc < 0) printf("[RT] waiting...\n");
  write(1, buf, strlen(buf) + 1);
  close(sfd);
  return EXIT_SUCCESS;
}
