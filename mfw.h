#ifndef _MFW_H_
#define _MFW_H_

#include <stdint.h>
#include <linux/types.h>

#define DEVICE_INTF_NAME "/dev/mfw"

// Protocols
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// Operation Modes
enum {
    MFW_NONE = 0,
    MFW_ADD,
    MFW_REMOVE,
    MFW_VIEW
};

// Structure for a single firewall rule
struct mfw_rule {
    int8_t in;             // 1 = in, 0 = out
    uint32_t s_ip;
    uint32_t s_mask;
    uint16_t s_port;
    uint32_t d_ip;
    uint32_t d_mask;
    uint16_t d_port;
    uint8_t proto;
};

// Instruction sent to kernel
struct mfw_ctl {
    uint8_t mode;
    struct mfw_rule rule;
};

#endif // _MFW_H_
#ifndef _MFW_H_
#define _MFW_H_

#include <stdint.h>
#include <linux/types.h>

#define DEVICE_INTF_NAME "/dev/mfw"

// Protocols
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// Operation Modes
enum {
    MFW_NONE = 0,
    MFW_ADD,
    MFW_REMOVE,
    MFW_VIEW
};

// Structure for a single firewall rule
struct mfw_rule {
    int8_t in;             // 1 = in, 0 = out
    uint32_t s_ip;
    uint32_t s_mask;
    uint16_t s_port;
    uint32_t d_ip;
    uint32_t d_mask;
    uint16_t d_port;
    uint8_t proto;
};

// Instruction sent to kernel
struct mfw_ctl {
    uint8_t mode;
    struct mfw_rule rule;
};

#endif // _MFW_H_
