// kernel/mfw_kmod.h

#ifndef MFW_KMOD_H
#define MFW_KMOD_H

#include <linux/types.h>
#include <linux/list.h>

#define MFW_ADD    1
#define MFW_REMOVE 2
#define MFW_VIEW   3

struct mfw_rule {
    int in; // 1 for in, 0 for out
    __be32 s_ip;
    __be32 s_mask;
    __be16 s_port;

    __be32 d_ip;
    __be32 d_mask;
    __be16 d_port;

    uint8_t proto;

    // IPv6 Support (Optional Extension)
    struct in6_addr s_ip6;
    struct in6_addr s_mask6;
    struct in6_addr d_ip6;
    struct in6_addr d_mask6;

    struct list_head list;
};

struct mfw_ctl {
    int mode;
    struct mfw_rule rule;
};

#endif
