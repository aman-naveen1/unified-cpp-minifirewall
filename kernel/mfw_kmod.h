#ifndef MFW_KMOD_H
#define MFW_KMOD_H

#include <linux/types.h>

#define DEVICE_NAME "mfw"
#define DEVICE_INTF_NAME "/dev/mfw"

#define MFW_NONE    0
#define MFW_ADD     1
#define MFW_REMOVE  2
#define MFW_VIEW    3

struct mfw_rule {
    __u8  in;       // 1 for incoming, 0 for outgoing
    __u32 s_ip;     // Source IP
    __u32 s_mask;   // Source subnet mask
    __u16 s_port;   // Source port
    __u32 d_ip;     // Destination IP
    __u32 d_mask;   // Destination subnet mask
    __u16 d_port;   // Destination port
    __u8  proto;    // Protocol (TCP=6, UDP=17)
};

struct mfw_ctl {
    __u8 mode;          // MFW_ADD, MFW_REMOVE, MFW_VIEW
    struct mfw_rule rule;
};

#endif // MFW_KMOD_H
