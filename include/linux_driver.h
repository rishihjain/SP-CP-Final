/* linux_driver.h */

#ifndef _TEST_TASK_LINUX_DRIVER_H_
#define _TEST_TASK_LINUX_DRIVER_H_

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/ioctl.h>

/* Device and Driver Definitions */
#define DEVICE_NAME         "test_task_dev"
#define DRIVER_NAME         "linux_driver"
#define DEVICE_CLASS_NAME   "test_task_dev_class"
#define MAX_DEVICES         4  /* Maximum number of device instances */

#ifdef __KERNEL__

/* Kernel-Space Device Buffer Information Structure */
typedef struct {
    ktime_t last_read_time;
    ktime_t last_write_time;
    pid_t  last_read_pid;
    pid_t  last_write_pid;
    uid_t  last_read_owner;
    uid_t  last_write_owner;
    size_t head;
    size_t tail;
    struct mutex buffer_lock;
    struct fasync_struct *fasync_queue;
    size_t total_reads;
    size_t total_writes;
    char *device_buffer;   /* Per-device buffer */
    size_t buffer_size;    /* Per-device buffer size */
    int is_blocking;       /* Blocking mode flag */
} dev_buf_info_t;

/* Kernel-Space Driver Statistics Structure */
typedef struct {
    size_t total_reads;
    size_t total_writes;
    size_t buffer_overflows;
    size_t buffer_underflows;
} driver_stats_t;

/* User-Space Structures for IOCTL in Kernel */
typedef struct {
    long long last_read_time;  /* Nanoseconds */
    long long last_write_time; /* Nanoseconds */
    pid_t last_read_pid;
    pid_t last_write_pid;
    uid_t last_read_owner;
    uid_t last_write_owner;
    size_t head;
    size_t tail;
    size_t total_reads;
    size_t total_writes;
} dev_buf_info_user_t;

typedef struct {
    size_t total_reads;
    size_t total_writes;
    size_t buffer_overflows;
    size_t buffer_underflows;
} driver_stats_user_t;

/* IOCTL Commands for Kernel Space */
#define IOCTL_BLOCK             _IO('k', 0)
#define IOCTL_NONBLOCK          _IO('k', 1)
#define IOCTL_BUFINFO           _IOR('k', 2, dev_buf_info_user_t)  /* User-space struct */
#define IOCTL_SET_BUFFER_SIZE   _IOW('k', 3, int)
#define IOCTL_GET_STATS         _IOR('k', 4, driver_stats_user_t)

/* Function Prototypes for Kernel Space */
static int dev_open(struct inode *inode, struct file *file);
static int dev_release(struct inode *inode, struct file *file);
static ssize_t dev_read(struct file *file, char __user *buffer, size_t length, loff_t *offset);
static ssize_t dev_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset);
static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int dev_mmap(struct file *filp, struct vm_area_struct *vma);
static int dev_fasync(int fd, struct file *filp, int mode);
static unsigned int dev_poll(struct file *file, poll_table *wait);
static int dev_suspend(struct device *dev);
static int dev_resume(struct device *dev);

/* Module Initialization and Exit */
static int __init linux_driver_init(void);
static void __exit linux_driver_exit(void);

#else /* User-Space Structures and IOCTL Definitions */

/* User-Space Device Buffer Information Structure */
typedef struct {
    long long last_read_time;  /* Nanoseconds */
    long long last_write_time; /* Nanoseconds */
    pid_t last_read_pid;
    pid_t last_write_pid;
    uid_t last_read_owner;
    uid_t last_write_owner;
    size_t head;
    size_t tail;
    size_t total_reads;
    size_t total_writes;
} dev_buf_info_user_t;

/* User-Space Driver Statistics Structure */
typedef struct {
    size_t total_reads;
    size_t total_writes;
    size_t buffer_overflows;
    size_t buffer_underflows;
} driver_stats_user_t;

/* IOCTL Commands for User Space */
#define IOCTL_BLOCK             _IO('k', 0)
#define IOCTL_NONBLOCK          _IO('k', 1)
#define IOCTL_BUFINFO           _IOR('k', 2, dev_buf_info_user_t)
#define IOCTL_SET_BUFFER_SIZE   _IOW('k', 3, int)
#define IOCTL_GET_STATS         _IOR('k', 4, driver_stats_user_t)

#endif /* __KERNEL__ */

#endif /* _TEST_TASK_LINUX_DRIVER_H_ */

