#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h> /* for sprintf() */
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h> /* for get_user and put_user */
#include <linux/version.h>

#include <asm/errno.h>

#define SUB_ADD 0xDEADBEE0
#define SUB_FREE 0xDEADBEE1
#define SUB_DOSUB 0xDEADBEE2

#define MAX_SIZE (128 * 0x10 + 0x18)
#define MIN_SIZE (0x50 + 0x18)

#define NBUF 2
static char *bufs[NBUF];
static unsigned int bufs_free[NBUF] = {0};
static unsigned int sub_offset;
unsigned int size;

DEFINE_SPINLOCK(ioctl_lock);

static long sub_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  char *buf = NULL;
  unsigned long offset = arg;
  unsigned long nth_buf = arg;
  int i;

  spin_lock(&ioctl_lock);

  switch (cmd) {
  case SUB_ADD:
    for (i = 0; i < NBUF; i++) {
      if (bufs[i] == NULL) {
        break;
      }
    }

    if (buf) {
      spin_unlock(&ioctl_lock);
      return -EEXIST;
    }
    if (offset != 0 &&
        copy_to_user((void *)offset, &sub_offset, sizeof(sub_offset))) {
      spin_unlock(&ioctl_lock);
      return -EINVAL;
    }
    bufs[i] = (char *)kzalloc(size, GFP_KERNEL_ACCOUNT);
    spin_unlock(&ioctl_lock);
    return size;
  case SUB_FREE:
    if (nth_buf > NBUF) {
      spin_unlock(&ioctl_lock);
      return -EINVAL;
    }
    if (bufs_free[nth_buf] == 0) {
      kfree(bufs[nth_buf]);
      bufs_free[nth_buf] = 1;
    }
    spin_unlock(&ioctl_lock);
    return 0;
  case SUB_DOSUB:
    if (nth_buf > NBUF) {
      spin_unlock(&ioctl_lock);
      return -EINVAL;
    }
    buf = bufs[nth_buf];
    if (buf != NULL && sub_offset != 0) {
      (*(int *)&buf[sub_offset])--;
      // sub_offset = 0;
      spin_unlock(&ioctl_lock);
      return 0;
    } else {
      spin_unlock(&ioctl_lock);
      return -ENOENT;
    }
  default:
    spin_unlock(&ioctl_lock);
    return -EINVAL;
  };
}

enum {
  CDEV_NOT_USED = 0,
  CDEV_EXCLUSIVE_OPEN = 1,
};

/* Is device open? Used to prevent multiple access to device */
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static int sub_open(struct inode *inode, struct file *file) {

  if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
    return -EBUSY;

  try_module_get(THIS_MODULE);

  return 0;
}

int sub_release(struct inode *inode, struct file *file) {
  /* We're now ready for our next caller */
  atomic_set(&already_open, CDEV_NOT_USED);

  /* Decrement the usage count, or else once you opened the file, you will
   * never get rid of the module.
   */
  module_put(THIS_MODULE);
  return 0;
}

static const struct file_operations sub_fops = {
    .unlocked_ioctl = sub_ioctl,
    .open = sub_open,
    .release = sub_release,
    .owner = THIS_MODULE,
};

#define DEVICE_NAME "n1sub"
static struct class *cls;
static int major;

int init_module(void) {
  struct device *dev;

  major = register_chrdev(0, DEVICE_NAME, &sub_fops);
  if (major < 0) {
    return major;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
  cls = class_create(DEVICE_NAME);
#else
  cls = class_create(THIS_MODULE, DEVICE_NAME);
#endif
  if (IS_ERR(cls)) {
    unregister_chrdev(major, DEVICE_NAME);
    return PTR_ERR(cls);
  }
  dev = device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
  if (IS_ERR(dev)) {
    class_destroy(cls);
    unregister_chrdev(major, DEVICE_NAME);
    return PTR_ERR(dev);
  }
  pr_info("Device created on /dev/%s\n", DEVICE_NAME);

  size = get_random_u32() % (MAX_SIZE - MIN_SIZE) + MIN_SIZE;
  sub_offset = get_random_u32() % (size - 0x50) + 0x50;
  sub_offset = sub_offset & (~(8 - 1));
  return 0;
}

void cleanup_module(void) {
  device_destroy(cls, MKDEV(major, 0));
  class_destroy(cls);

  unregister_chrdev(major, DEVICE_NAME);
}

MODULE_LICENSE("GPL");
