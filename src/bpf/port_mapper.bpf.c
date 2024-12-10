#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// vmlinux.h does not include kernel macros, so redefine relevant ones here.
#define AF_INET 2   /* Internet IP Protocol */
#define AF_INET6 10 /* IP version 6			*/

// The license declaration is send (by libbpf) to the kernel during BPF program load and, for libbpf, applies to all BPF programs within the same BPF-binary.
// Certain features are only unlocked by the kernel if the program declares a GPL-compatible license.
// This license only applies to the BPF program(s), but not necessarily to the userspace program.
// TODO: Determine the license we want to use here.
char LICENSE[] SEC("license") = "Proprietary"; // We're not actually propretiary - this file is licensed under the same conditions as the main project.
// However, we need to tell the kernel that we're not GPLv2.

// This map holds references to the socket where the HTTP-01 challenge solver listens on.
// entry 0 is for the IPv4 socket, entry 1 for IPv6 (no dualstack socket for compatibility)
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} solver_socket SEC(".maps");

// Constants are configured by userspace during BPF program loading
const volatile u32 CHALLENGE_PORT;

#define LOCALHOST_IPV4 0x7f000001 // 127.0.0.1

// This BPF program redirects all socket lookups targeting the challenge port to the challenge solver, which can then answer
// challenge requests with the proper response and reverse proxy other requests to the actual HTTP server.
SEC("sk_lookup")
int proxy_challenge(struct bpf_sk_lookup* ctx) {
    if (ctx->family != AF_INET && ctx->family != AF_INET6) {
        return SK_PASS;
    }
    if (ctx->protocol != IPPROTO_TCP || ctx->local_port != CHALLENGE_PORT) {
        return SK_PASS;
    }

    // Verify that this request is not the challenge solver itself trying to connect to the HTTP server.
    // We're filtering broadly here by allowing any IPv4 localhost connection to bypass the proxy.
    if (ctx->family == AF_INET) {
        u32 remote_ipv4 = bpf_ntohl(ctx->remote_ip4);
        if (remote_ipv4 == LOCALHOST_IPV4) {
            return SK_PASS;
        }
    }
    struct bpf_sock* sk;
    // Select either the IPv4 socket or IPv6 socket depending on what the remote is looking for.
    __u32 idx = ctx->family == AF_INET ? 0 : 1;
    sk = bpf_map_lookup_elem(&solver_socket, &idx);
    if (!sk)
        return SK_PASS;
    bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return SK_PASS;
}