#ifndef MFW_H
#define MFW_H

#include <linux/types.h>

#define DEVICE_PATH "/dev/minifw"

struct mfw_rule {
    int in;
    uint8_t ip_version;

    union {
        __u32 s_ip4;
        __u8 s_ip6[16];
    };
    union {
        __u32 s_mask4;
        __u8 s_mask6[16];
    };
    __u16 s_port;

    union {
        __u32 d_ip4;
        __u8 d_ip6[16];
    };
    union {
        __u32 d_mask4;
        __u8 d_mask6[16];
    };
    __u16 d_port;

    __u8 proto;
};

struct mfw_ctl {
    int mode;
    struct mfw_rule rule;
};

#define MFW_NONE    0
#define MFW_ADD     1
#define MFW_REMOVE  2
#define MFW_VIEW    3

#endif
