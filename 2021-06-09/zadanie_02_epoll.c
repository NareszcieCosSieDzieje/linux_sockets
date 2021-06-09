/*
 * Compilation:  gcc -Wall ./zadanie_02_epoll.c -o ./zadanie_02_epoll
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>   
#include <sys/epoll.h> 
#include <string.h>  
#include <fcntl.h>

#define ERROR(e) { perror(e); exit(EXIT_FAILURE); }
#define SERVER_PORT 1234
#define QUEUE_SIZE 5
#define MAX_EVENTS 10


int make_socket_non_blocking(int sfd) {
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("Fcntl get socket flags.");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("Fcntl set socket non-blocking.\n");
        return -1;
    }
    return 0;
}



int main(int argc, char** argv) {
    socklen_t slt;
    int sfd, cfd, i, on = 1;
    struct sockaddr_in saddr, caddr;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(SERVER_PORT);

    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        ERROR("socket()")
    }
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)) < 0) {
        ERROR("setsockopt()")
    }
    if (bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
        ERROR("bind()")
    }
    if (listen(sfd, QUEUE_SIZE) < 0){
        ERROR("listen()")
    }

    struct epoll_event event, events[MAX_EVENTS];
    int epoll_fd = epoll_create1(0);

    if(epoll_fd == -1) {
        fprintf(stderr, "Failed to create epoll file descriptor\n");
        return 1;
    }

    event.events = EPOLLIN;
    event.data.fd = sfd;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, 0, &event)) {
        fprintf(stderr, "Failed to add file descriptor to epoll\n");
        close(epoll_fd);
        return 1;
    }

    while(1) {

        int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS - 1, 5000);
        if (event_count < 0) {
            ERROR("epoll wait()")
        }

        if (event_count == 0) { 
            printf("timed out\n");
            continue;
        }

        for(i = 0; i < event_count; i++) {
            if (events[i].data.fd == sfd) {
                slt = sizeof(caddr);
                if ((cfd = accept(sfd, (struct sockaddr*)&caddr, &slt)) < 0) {
                    ERROR("accept()")
                }
                printf("new connection: %s\n", inet_ntoa((struct in_addr)caddr.sin_addr));
                make_socket_non_blocking(cfd);
                event.events = EPOLLOUT;
                event.data.fd = cfd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &event);
            } else {
                write(events[i].data.fd, "Hello World!\n", 13);
                close(events[i].data.fd);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
            }
        }
    }
    close(sfd);
    return EXIT_SUCCESS;
}

