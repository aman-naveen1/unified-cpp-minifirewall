#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "mfw_kmod.h"

#define MAX_RULES 100
#define CLASS_NAME "mfw_class"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MiniFirewall Unified");
MODULE_DESCRIPTION("A Unified MiniFirewall Kernel Module supporting IPv4 and IPv6");
MODULE_VERSION("2.0");

static struct mfw_rule rule_list[MAX_RULES];
static int rule_count = 0;

static int major;
static struct class*  mfw_class  = NULL;
static struct device* mfw_device = NULL;

/*
 * Match function for packet filtering
 */
static bool match_rule(const struct mfw_rule *r, struct sk_buff *skb, bool is_ipv6) {
    __u32 s_ip = 0, d_ip = 0;
    __u16 s_port = 0, d_port = 0;
    __u8 proto = 0;

    if (is_ipv6)
        return false; // IPv6 matching not yet implemented in this rule structure

    struct iphdr *iph = ip_hdr(skb);
    if (!iph)
        return false;

    proto = iph->protocol;
    s_ip = ntohl(iph->saddr);
    d_ip = ntohl(iph->daddr);

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        s_port = ntohs(tcph->source);
        d_port = ntohs(tcph->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = udp_hdr(skb);
        s_port = ntohs(udph->source);
        d_port = ntohs(udph->dest);
    }

    if ((r->proto != 0 && r->proto != proto) ||
        ((r->s_ip & r->s_mask) != (s_ip & r->s_mask)) ||
        ((r->d_ip & r->d_mask) != (d_ip & r->d_mask)) ||
        (r->s_port != 0 && r->s_port != htons(s_port)) ||
        (r->d_port != 0 && r->d_port != htons(d_port)))
        return false;

    return true;
}

/*
 * Hook function
 */
static unsigned int hook_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    int i;
    bool is_ipv6 = (skb->protocol == htons(ETH_P_IPV6));

    for (i = 0; i < rule_count; ++i) {
        if ((rule_list[i].in && state->hook == NF_INET_PRE_ROUTING) ||
            (!rule_list[i].in && state->hook == NF_INET_POST_ROUTING)) {
            if (match_rule(&rule_list[i], skb, is_ipv6))
                return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_ipv4 = {
    .hook     = hook_fn,
    .pf       = PF_INET,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfho_ipv4_out = {
    .hook     = hook_fn,
    .pf       = PF_INET,
    .hooknum  = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

/*
 * Device operations
 */
static ssize_t dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset) {
    if (*offset >= rule_count * sizeof(struct mfw_rule))
        return 0;

    if (copy_to_user(buf, &rule_list[*offset / sizeof(struct mfw_rule)], sizeof(struct mfw_rule)))
        return -EFAULT;

    *offset += sizeof(struct mfw_rule);
    return sizeof(struct mfw_rule);
}

static ssize_t dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset) {
    struct mfw_ctl ctl;

    if (count != sizeof(struct mfw_ctl))
        return -EINVAL;

    if (copy_from_user(&ctl, buf, sizeof(ctl)))
        return -EFAULT;

    switch (ctl.mode) {
        case MFW_ADD:
            if (rule_count >= MAX_RULES)
                return -ENOMEM;
            rule_list[rule_count++] = ctl.rule;
            break;

        case MFW_REMOVE: {
            int i;
            for (i = 0; i < rule_count; ++i) {
                if (memcmp(&rule_list[i], &ctl.rule, sizeof(struct mfw_rule)) == 0) {
                    memmove(&rule_list[i], &rule_list[i+1], (rule_count - i - 1) * sizeof(struct mfw_rule));
                    rule_count--;
                    break;
                }
            }
            break;
        }
        default:
            return -EINVAL;
    }

    return count;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = dev_read,
    .write = dev_write
};

/*
 * Module init
 */
static int __init mfw_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "MiniFirewall failed to register device\n");
        return major;
    }

    mfw_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(mfw_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        return PTR_ERR(mfw_class);
    }

    mfw_device = device_create(mfw_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mfw_device)) {
        class_destroy(mfw_class);
        unregister_chrdev(major, DEVICE_NAME);
        return PTR_ERR(mfw_device);
    }

    nf_register_net_hook(&init_net, &nfho_ipv4);
    nf_register_net_hook(&init_net, &nfho_ipv4_out);

    printk(KERN_INFO "MiniFirewall kernel module loaded.\n");
    return 0;
}

/*
 * Module exit
 */
static void __exit mfw_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho_ipv4);
    nf_unregister_net_hook(&init_net, &nfho_ipv4_out);
    device_destroy(mfw_class, MKDEV(major, 0));
    class_destroy(mfw_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "MiniFirewall kernel module unloaded.\n");
}

module_init(mfw_init);
module_exit(mfw_exit);
