#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <string.h>  
#include <netdb.h> 
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

#define NUM_THREADS 2
#define MAX_EVENTS 64

struct server_data {
    struct hostent* main_ip_address;
    long main_port_number;
    struct hostent* sub_ip_address;
    long sub_port_number;
};

int send_signal(int pid);

void sig_handler(int signo);

int make_socket_non_blocking(int sfd);

void* server_main(void* server_data);
void* server_sub(void* server_data);

void abort();

pid_t main_thread_id = -1;
pthread_t threads[NUM_THREADS];


int main(int argc, char** argv) {

    if (signal(SIGINT, sig_handler) == SIG_ERR){
        perror("Cannot intercept SIGINT\n");
        exit(-1);
    }

    main_thread_id = gettid();   

    pthread_attr_t attr;

    int rv = -1;
    long tid = 0;
    void *status;

    struct hostent* sub_server_ip_address;
    long sub_server_port_number = -1;

    struct server_data all_server_data;  

    if (argc < 3){
        printf("Server IP and PORT arguments not present. Exiting.\n");
        exit(-1);
    } else {
        sub_server_ip_address = gethostbyname(argv[1]);
        sub_server_port_number = strtol(argv[2], NULL, 10);
        if (sub_server_port_number == NULL || sub_server_port_number < 0){
            perror("Port cast error\n");
            exit(-2);
        }
        printf("got %ld\n", sub_server_port_number);
    }

    all_server_data.main_ip_address = htonl(INADDR_ANY); //gethostbyname("127.0.0.1");
    all_server_data.main_port_number = 1234; 
    all_server_data.sub_ip_address = sub_server_ip_address;
    all_server_data.sub_port_number = sub_server_port_number;

    if (all_server_data.main_port_number == all_server_data.sub_port_number){
        perror("Port same as main server's. Try something different than 1234.\n");
        exit(-3);
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    rv = pthread_create(&threads[tid], &attr, server_main, (void*)&all_server_data);
    if (rv != 0){
        printf("ERROR. Return code from pthread_create() for server_main is %d\n", rv);
        exit(-1);
    }
    tid = 1;
    rv = pthread_create(&threads[tid], &attr, server_sub, (void*)&all_server_data);
    if (rv != 0){
        printf("ERROR. Return code from pthread_create() for server_sub is %d\n", rv);
        exit(-1);
    }

    pthread_attr_destroy(&attr);

    for(tid=0; tid<NUM_THREADS; tid++) {
        rv = pthread_join(threads[tid], &status);
        if (rv != 0) {
            printf("ERROR; return code from pthread_join() is %d\n", rv);
            exit(-1);
        }
    }
}

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

void sig_handler(int signo)
{
    if(signo == SIGINT){
        pid_t current_id = gettid();
        printf("\nSIG INT INTERCEPTED in %d\n", current_id);
        if (current_id == main_thread_id){
            abort();
        }
        pthread_exit(NULL);
    }  
}


int send_signal(int pid)
{
    int ret;
    ret = kill(pid, SIGINT);
    printf("ret : %d",ret);
}


void abort(){
    // zwolnij zasoby
    // send_signal(main_thread_id);
    for(int i = 0; i < NUM_THREADS; i++ ) {
        pthread_kill(threads[i], SIGINT);
    }
}

void* server_main(void* _server_data)
{

    struct server_data *all_server_data = (struct server_data*)_server_data;

    struct sockaddr_in sub_addr;

    memset(&sub_addr, 0, sizeof(sub_addr));
    sub_addr.sin_family = AF_INET;
    sub_addr.sin_port = (*all_server_data).sub_port_number;
    memcpy(&sub_addr.sin_addr.s_addr, (*all_server_data).sub_ip_address->h_addr, (*all_server_data).sub_ip_address->h_length);

    long server_port = (*all_server_data).main_port_number;    

    socklen_t sl;
    int sfd, cfd, on = 1;
    struct sockaddr_in saddr, caddr;

    int efd;
    struct epoll_event event;
    struct epoll_event* events;

    int rv = -1;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(server_port);

    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) {
        perror("Socket creation for main server.\n");
        abort();
    }
    rv = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*) &on, sizeof(on));
    if (rv == -1){
        perror("Setsockopt for main server.\n");
        close(sfd);
        abort();
    }
    rv = bind(sfd, (struct sockaddr*) &saddr, sizeof(saddr));
    if (rv != 0){
        perror("Socket bind for main server.\n");
        close(sfd);
        abort();
    }

    rv = make_socket_non_blocking(sfd);
    if (rv == -1){
        close(sfd);
        abort ();
    }

    efd = epoll_create1(0);
    if (efd == -1) {
        perror("Epoll create1 for main server.\n");
        close(sfd);
        abort();
    }

    event.data.fd = sfd;
    event.events = EPOLLIN;
    rv = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (rv == -1) {
        perror ("Failed to add fd to epoll.\n");
        close(sfd);
        close(efd);
        abort();
    }

    events = calloc(MAX_EVENTS, sizeof(event));

    while (1) {
        int n, i, s;
        n = epoll_wait(efd, events, MAX_EVENTS, -1);
        
        for (i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP) ||
                    (!(events[i].events & EPOLLIN)))
            {
                fprintf(stderr, "epoll error\n");
                close(events[i].data.fd);
                continue;
            }
            else if (sfd == events[i].data.fd) {

                struct sockaddr_in caddr;

                char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
                  
                while(1) {
                    ssize_t count;
                    char buf[512];

                    memset(&caddr, 0, sizeof(caddr));
                    memset(&buf, 0, sizeof(buf));
                    sl = sizeof(caddr);

                    count = recvfrom(sfd, buf, sizeof(buf)/sizeof(char), 0, (struct sockaddr*) &caddr, &sl);
                    if (count == -1) {
                        if (errno != EAGAIN)
                        {
                            perror("Read from client in main error.\n");
                        }
                        break;
                    }
                    else if (count == 0)
                    {
                        break;
                    }

                    s = getnameinfo(&caddr, sl,
                                    hbuf, sizeof(hbuf),
                                    sbuf, sizeof(sbuf),
                                    NI_NUMERICHOST | NI_NUMERICSERV);
                    if (s == 0) {
                        printf("Main server read bytes from connection "
                                "(host=%s, port=%s)\n", hbuf, sbuf);
                    }

                    s = sendto(sfd, buf, count, 0, (struct sockaddr*) &sub_addr, sizeof(sub_addr));
                    if (s == -1) {
                        perror("Write to sub server from main error.\n");
                        close(sfd);
                        close(efd);
                        close(cfd);
                        abort();
                    }
                }
            }
        }
    }
    free(events);
    close(efd);
    close(sfd);
    pthread_exit(NULL);
}


void* server_sub(void* _server_data)
{
    struct server_data *all_server_data = (struct server_data*)_server_data;
        
    socklen_t sl;
    int sfd, cfd, on = 1;
    struct sockaddr_in saddr, caddr;

    int efd;
    struct epoll_event event;
    struct epoll_event* events;

    int rv = -1;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = (*all_server_data).sub_port_number;
    memcpy(&saddr.sin_addr.s_addr, (*all_server_data).sub_ip_address->h_addr, (*all_server_data).sub_ip_address->h_length);

    // saddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //(*all_server_data).sub_ip_address; 

    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) {
        perror("Socket creation for sub server.\n");
        abort();
    }
    rv = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*) &on, sizeof(on));
    if (rv == -1){
        perror("Setsockopt for sub server.\n");
        close(sfd);
        abort();
    }
    rv = bind(sfd, (struct sockaddr*) &saddr, sizeof(saddr));
    if (rv != 0){
        perror("Socket bind for sub server.\n");
        close(sfd);
        abort();
    }

    rv = make_socket_non_blocking(sfd);
    if (rv == -1){
        perror("Sub server make non blocking.\n");
        close(sfd);
        abort ();
    }

    efd = epoll_create1(0);
    if (efd == -1) {
        perror("Epoll create1 for sub server.\n");
        close(sfd);
        abort();
    }

    event.data.fd = sfd;
    event.events = EPOLLIN;
    rv = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (rv == -1) {
        perror ("Failed to add fd to epoll in sub server.\n");
        close(sfd);
        close(efd);
        abort();
    }

    events = calloc(MAX_EVENTS, sizeof(event));

    while (1) {
        int n, i, s;
        n = epoll_wait(efd, events, MAX_EVENTS, -1);
        
        for (i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP) ||
                    (!(events[i].events & EPOLLIN)))
            {
                fprintf(stderr, "epoll error\n");
                close(events[i].data.fd);
                continue;
            }
            else if (sfd == events[i].data.fd) {
               
                struct sockaddr_in caddr;

                char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                while(1) {
                    ssize_t count;
                    char buf[512];

                    memset(&caddr, 0, sizeof(caddr));
                    memset(&buf, 0, sizeof(buf));
                    sl = sizeof(caddr);

                    count = recvfrom(sfd, buf, sizeof(buf)/sizeof(char), 0, (struct sockaddr*) &caddr, &sl);
                    if (count == -1) {

                        if (errno != EAGAIN)
                        {
                            perror("Read from main sub server error.\n");
                        }
                        break;
                    }
                    else if (count == 0)
                    {
                        break;
                    }

                    s = getnameinfo(&caddr, sl,
                                    hbuf, sizeof(hbuf),
                                    sbuf, sizeof(sbuf),
                                    NI_NUMERICHOST | NI_NUMERICSERV);
                    if (s == 0) {
                        printf("Sub server read bytes from connection "
                                "(host=%s, port=%s)\n", hbuf, sbuf);
                    }

                    s = write(1, buf, count);
                    if (s == -1) {
                        perror("Write to stdout from sub error.\n");
                        close(sfd);
                        close(efd);
                        abort();
                    }
                }
            }
        }
    }
    free(events);
    close(sfd);
    close(efd);
    pthread_exit(NULL);
}



