// CI connection prober. Prints "OK" when the connection (TCP) or send (UDP) succeeds.
//   prober [-b srcip] [-u|-c] host port [timeout_ms]
//   -u  UDP sendto on an unconnected socket   -c  UDP on a connected socket
// Built setuid-root (root:admin 4750) it behaves like FlClash's authorized core:
// effective uid 0 with the caller's group.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *bind_ip = NULL;
    int mode = 0;  // 0 tcp, 1 udp unconnected, 2 udp connected
    int opt;
    while ((opt = getopt(argc, argv, "b:uc")) != -1) {
        if (opt == 'b') bind_ip = optarg;
        else if (opt == 'u') mode = 1;
        else if (opt == 'c') mode = 2;
        else return 2;
    }
    if (argc - optind < 2) {
        fprintf(stderr, "usage: prober [-b src] [-u|-c] host port [timeout_ms]\n");
        return 2;
    }
    const char *host = argv[optind];
    int port = atoi(argv[optind + 1]);
    int timeout_ms = argc - optind > 2 ? atoi(argv[optind + 2]) : 3000;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &dst.sin_addr) != 1) { fprintf(stderr, "bad host\n"); return 2; }

    int s = socket(AF_INET, mode ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (s < 0) { printf("FAIL socket %s\n", strerror(errno)); return 1; }
    if (bind_ip) {
        struct sockaddr_in src;
        memset(&src, 0, sizeof src);
        src.sin_family = AF_INET;
        inet_pton(AF_INET, bind_ip, &src.sin_addr);
        if (bind(s, (struct sockaddr *)&src, sizeof src) != 0) { printf("FAIL bind %s\n", strerror(errno)); return 3; }
    }
    if (mode == 1) {
        ssize_t n = sendto(s, "ng", 2, 0, (struct sockaddr *)&dst, sizeof dst);
        printf(n == 2 ? "OK\n" : "FAIL sendto %s\n", strerror(errno));
        return n == 2 ? 0 : 1;
    }
    if (mode == 2) {
        if (connect(s, (struct sockaddr *)&dst, sizeof dst) != 0) { printf("FAIL connect %s\n", strerror(errno)); return 1; }
        ssize_t n = send(s, "ng", 2, 0);
        printf(n == 2 ? "OK\n" : "FAIL send %s\n", strerror(errno));
        return n == 2 ? 0 : 1;
    }
    fcntl(s, F_SETFL, O_NONBLOCK);
    int r = connect(s, (struct sockaddr *)&dst, sizeof dst);
    if (r != 0 && errno != EINPROGRESS) { printf("FAIL connect %s\n", strerror(errno)); return 1; }
    if (r != 0) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(s, &w);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select(s + 1, NULL, &w, NULL, &tv) <= 0) { printf("FAIL timeout\n"); return 1; }
        int err = 0;
        socklen_t len = sizeof err;
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err) { printf("FAIL %s\n", strerror(err)); return 1; }
    }
    printf("OK\n");
    close(s);
    return 0;
}
