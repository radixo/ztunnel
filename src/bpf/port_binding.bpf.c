#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// hard declarations
#define AF_INET     2
#define AF_INET6    10

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u8);
} mesh_ip4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u64);
} redir_map_ip4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_map SEC(".maps");

SEC("sk_lookup")
int port_binding(struct bpf_sk_lookup *ctx)
{
    struct bpf_sock *sk;
    __u32 ip;
    __u8 *exists;
    __u32 key = 0;
    __u64 *value;
    int err;

    bpf_printk("port_binding: new connection lookup");

    if (ctx->protocol != IPPROTO_TCP) {
        bpf_printk("port_binding: not TCP protocol (%d), skipping", ctx->protocol);
        return SK_PASS;
    }

    // XXX first version only supports IPv4
    if (ctx->family != AF_INET) {
        bpf_printk("port_binding: not IPv4 family (%d), skipping", ctx->family);
        return SK_PASS;
    }

    if (ctx->local_port == 15006) {
        return SK_PASS; // skip port 15006
    }

    // Extract octets from local_ip4
    __u8 local_ip_a = (ctx->local_ip4) & 0xFF;
    __u8 local_ip_b = (ctx->local_ip4 >> 8) & 0xFF;
    __u8 local_ip_c = (ctx->local_ip4 >> 16) & 0xFF;
    __u8 local_ip_d = (ctx->local_ip4 >> 24) & 0xFF;

    // Extract octets from remote_ip4
    __u8 remote_ip_a = (ctx->remote_ip4) & 0xFF;
    __u8 remote_ip_b = (ctx->remote_ip4 >> 8) & 0xFF;
    __u8 remote_ip_c = (ctx->remote_ip4 >> 16) & 0xFF;
    __u8 remote_ip_d = (ctx->remote_ip4 >> 24) & 0xFF;

    // Log IPs and ports in human-readable format
    bpf_printk("Local: %d.%d.%d.%d:%d, Remote: %d.%d.%d.%d:%d",
               local_ip_a, local_ip_b, local_ip_c, local_ip_d, ctx->local_port,
               remote_ip_a, remote_ip_b, remote_ip_c, remote_ip_d, ctx->remote_port);
    bpf_printk("ingress_ifindex: %d", ctx->ingress_ifindex);

    ip = ctx->remote_ip4;
    bpf_printk("port_binding: checking remote_ip4: %u", ip);

    exists = bpf_map_lookup_elem(&mesh_ip4, &ip);
    if (!exists) {
        bpf_printk("port_binding: remote_ip4 not in mesh_ip4 map, skipping");
        return SK_PASS;
    }

    ip = ctx->local_ip4;
    bpf_printk("port_binding: looking up local_ip4: %u in redir_map", ip);
    
    sk = bpf_map_lookup_elem(&redir_map_ip4, &ip);
    if (!sk) {
        bpf_printk("port_binding: no socket in redir_map for local_ip4, skipping");
        return SK_PASS;
    }

    value = bpf_map_lookup_elem(&global_map, &key);
    if (!value) {
        __u64 new_value = 1;
        bpf_map_update_elem(&global_map, &key, &new_value, BPF_ANY);
    } else if (*value < 3) {
        (*value)++;
        bpf_map_update_elem(&global_map, &key, value, BPF_ANY);
    } else {
        bpf_sk_release(sk);
        return SK_PASS;
    }

    bpf_printk("port_binding: found socket, assigning");
    err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    
    if (err) {
        bpf_printk("port_binding: socket assignment failed with error %d", err);
        return SK_DROP;
    }

    bpf_printk("port_binding: socket assignment successful");
    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";