#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/types.h>        
#include <sys/socket.h>

int main(int argc, char** argv[]){

    if (argc < 3) {
        perror("Not enough arguments. Exiting.\n");
        exit(1);
    }

    char** interface_name = argv[1];
    char** interface_switch = argv[2];
    if (strcmp((const char*)interface_switch, "up") == 0 || strcmp((const char*)interface_switch, "down") == 0) {
        ;
    } else {
        perror("Wrong interface switch. Try \'up\', \'down\'\n");
        exit(2);
    }
    int sfd;
    struct ifreq ifr;
    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, (const char* restrict)interface_name, IFNAMSIZ);

    ioctl(sfd, SIOCGIFFLAGS, &ifr);
    if (strcasecmp((const char*)interface_switch, "up") == 0) {
        ifr.ifr_flags |= IFF_UP;
    } else if (strcasecmp((const char*)interface_switch, "down") == 0) {
      ifr.ifr_flags &= ~IFF_UP;
    }

    int ret = ioctl(sfd, SIOCSIFFLAGS, &ifr);
    if (ret != -1){
        printf("Interface %s set %s\n", interface_name, interface_switch);
    } else {
        printf("Wrong interface name.\n");
    }

    return 0;
}


