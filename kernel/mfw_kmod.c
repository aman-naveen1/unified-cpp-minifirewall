// kernel/mfw_kmod.c

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "mfw_kmod.h"

#define DEVICE_NAME "mfw"
#define CLASS_NAME "mfw_class"

static dev_t dev_num;
static struct cdev mfw_cdev;
static struct class *mfw_class;

static LIST_HEAD(rule_list);
static DEFINE_MUTEX(mfw_mutex);

static ssize_t mfw_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    struct mfw_rule *rule;
    static struct list_head *pos;
    static bool read_in_progress = false;

    if (!read_in_progress) {
        pos = rule_list.next;
        read_in_progress = true;
    }

    if (pos == &rule_list) {
        read_in_progress = false;
        return 0; // EOF
    }

    rule = list_entry(pos, struct mfw_rule, list);
    if (copy_to_user(buf, rule, sizeof(*rule)))
        return -EFAULT;

    pos = pos->next;
    return sizeof(*rule);
}

static ssize_t mfw_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    struct mfw_ctl ctl;
    struct mfw_rule *new_rule, *tmp;

    if (len != sizeof(struct mfw_ctl))
        return -EINVAL;

    if (copy_from_user(&ctl, buf, sizeof(struct mfw_ctl)))
        return -EFAULT;

    mutex_lock(&mfw_mutex);

    switch (ctl.mode) {
        case MFW_ADD:
            new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
            if (!new_rule) {
                mutex_unlock(&mfw_mutex);
                return -ENOMEM;
            }
            memcpy(new_rule, &ctl.rule, sizeof(*new_rule));
            INIT_LIST_HEAD(&new_rule->list);
            list_add_tail(&new_rule->list, &rule_list);
            break;

        case MFW_REMOVE:
            list_for_each_entry_safe(new_rule, tmp, &rule_list, list) {
                if (memcmp(&new_rule->in, &ctl.rule.in, sizeof(struct mfw_rule) - sizeof(struct list)) == 0) {
                    list_del(&new_rule->list);
                    kfree(new_rule);
                    break;
                }
            }
            break;

        default:
            mutex_unlock(&mfw_mutex);
            return -EINVAL;
    }

    mutex_unlock(&mfw_mutex);
    return sizeof(struct mfw_ctl);
}

static int mfw_open(struct inode *inode, struct file *file) { return 0; }
static int mfw_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = mfw_open,
    .release = mfw_release,
    .read = mfw_read,
    .write = mfw_write,
};

static int __init mfw_init(void)
{
    alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    cdev_init(&mfw_cdev, &fops);
    cdev_add(&mfw_cdev, dev_num, 1);

    mfw_class = class_create(THIS_MODULE, CLASS_NAME);
    device_create(mfw_class, NULL, dev_num, NULL, DEVICE_NAME);

    pr_info("MiniFirewall kernel module loaded\n");
    return 0;
}

static void __exit mfw_exit(void)
{
    struct mfw_rule *rule, *tmp;

    device_destroy(mfw_class, dev_num);
    class_destroy(mfw_class);
    cdev_del(&mfw_cdev);
    unregister_chrdev_region(dev_num, 1);

    list_for_each_entry_safe(rule, tmp, &rule_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    pr_info("MiniFirewall kernel module unloaded\n");
}

module_init(mfw_init);
module_exit(mfw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("Unified IPv4 and IPv6 MiniFirewall Kernel Module");
