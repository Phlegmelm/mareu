#include <string.h>
#include <unistd.h>

int parse_client_hello(int fd) {           // pre_auth entry, network
    char buf[64];
    int n = recv(fd, buf, 4096, 0);         // unchecked recv -> tainted n
    char dst[16];
    memcpy(dst, buf, n);                     // tainted size into memcpy
    return n;
}

void handle(char *user) {
    char tmp[32];
    strcpy(tmp, user);                       // unbounded copy
    printf(user);                            // not flagged (no pattern), ok
}
