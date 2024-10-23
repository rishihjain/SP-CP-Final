#include "../include/linux_driver.h"
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/wait.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/dynamic_debug.h>
#include <linux/kernel.h>
#include <asm/io.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander (@alkuzin)");
MODULE_DESCRIPTION("Enhanced Character device driver for inter-process communication");

/* Define module ring buffer size param */
static int buffer_size = 1024;
/* S_IRUGO - read permissions for the owner, group, and others */
module_param(buffer_size, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(buffer_size, "Ring buffer size");

/* Wait queues for read and write operations */
static DECLARE_WAIT_QUEUE_HEAD(read_queue);
static DECLARE_WAIT_QUEUE_HEAD(write_queue);

/* Device Buffer and Buffer Info */
static dev_buf_info_t buffer_info[MAX_DEVICES];
static struct mutex global_lock;

/* Device Numbers and Class */
static s32 major_number;
static struct class *dev_class;
static struct cdev char_device[MAX_DEVICES];
static struct device *device_instance[MAX_DEVICES];
static dev_t dev_number;

/* Device Statistics */
static driver_stats_t driver_stats;

/* Debugfs */
static struct dentry *debugfs_dir;
static struct dentry *debugfs_stats;

/* Kernel Thread */
static struct task_struct *kthread_task;

/* Function to handle kernel thread */
static int kernel_thread_func(void *data) {
    while (!kthread_should_stop()) {
        /* Example background task: Periodically log buffer status */
        msleep(5000); /* Sleep for 5 seconds */
        pr_debug("Kernel Thread: Total Reads: %zu, Total Writes: %zu\n",
                             driver_stats.total_reads, driver_stats.total_writes);
        /* Add more background tasks as needed */
    }
    return 0;
}

/* File Operations Structure */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = dev_open,
    .release        = dev_release,
    .read           = dev_read,
    .write          = dev_write,
    .unlocked_ioctl = dev_ioctl,
    .mmap           = dev_mmap,
    .fasync         = dev_fasync,
    .poll           = dev_poll,
};

/* Power Management Operations */
static const struct dev_pm_ops pm_ops = {
    .suspend = dev_suspend,
    .resume  = dev_resume,
};

/* Initialize Sysfs Attributes */
static ssize_t buffer_size_show(struct device *dev, struct device_attribute *attr, char *buf) {
    int minor = MINOR(dev->devt);
    dev_buf_info_t *info = &buffer_info[minor];
    return sprintf(buf, "%zu\n", info->buffer_size);
}

static ssize_t buffer_size_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    int new_size;
    int minor;
    dev_buf_info_t *info;

    if (sscanf(buf, "%d", &new_size) != 1)
        return -EINVAL;

    if (new_size <= 0)
        return -EINVAL;

    minor = MINOR(dev->devt);
    if (minor >= MAX_DEVICES)
        return -EINVAL;

    info = &buffer_info[minor];

    mutex_lock(&info->buffer_lock);
    kfree(info->device_buffer);
    info->device_buffer = kmalloc(new_size, GFP_KERNEL);
    if (!info->device_buffer) {
        mutex_unlock(&info->buffer_lock);
        return -ENOMEM;
    }
    info->buffer_size = new_size;
    memset(info->device_buffer, 0, info->buffer_size);
    mutex_unlock(&info->buffer_lock);
    return count;
}

static DEVICE_ATTR(buffer_size, S_IRUGO | S_IWUSR, buffer_size_show, buffer_size_store);

/* Debugfs Operations */
static ssize_t debugfs_stats_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    char buffer[256];
    int len;

    len = snprintf(buffer, sizeof(buffer),
                   "Total Reads: %zu\nTotal Writes: %zu\nBuffer Overflows: %zu\nBuffer Underflows: %zu\n",
                   driver_stats.total_reads,
                   driver_stats.total_writes,
                   driver_stats.buffer_overflows,
                   driver_stats.buffer_underflows);
    
    return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static const struct file_operations debugfs_fops = {
    .owner = THIS_MODULE,
    .read  = debugfs_stats_read,
};

/* Device Open Function */
static int dev_open(struct inode *inode, struct file *file)
{
    int minor = iminor(inode);
    if (minor >= MAX_DEVICES)
        return -ENODEV;

    printk(KERN_DEBUG DRIVER_NAME ": Device %d opened\n", minor);
    return 0;
}

/* Device Release Function */
static int dev_release(struct inode *inode, struct file *file)
{
    int minor = iminor(inode);
    dev_buf_info_t *info = &buffer_info[minor];

    /* Remove from fasync queue */
    fasync_helper(file->f_flags, file, -1, &info->fasync_queue);

    printk(KERN_DEBUG DRIVER_NAME ": Device %d released\n", minor);
    return 0;
}

/* Device Read Function */
static ssize_t dev_read(struct file *file, char __user *buffer, size_t length, loff_t *offset)
{
    int minor = iminor(file->f_inode);
    dev_buf_info_t *info = &buffer_info[minor];
    ssize_t bytes_read = 0;

    if (minor >= MAX_DEVICES)
        return -ENODEV;

    mutex_lock(&info->buffer_lock);

    /* Handle blocking/non-blocking mode */
    while (info->head == info->tail) {
        if (!info->is_blocking) {
            mutex_unlock(&info->buffer_lock);
            return -EAGAIN;
        }
        mutex_unlock(&info->buffer_lock);
        if (wait_event_interruptible(read_queue, info->head != info->tail))
            return -ERESTARTSYS;
        mutex_lock(&info->buffer_lock);
    }

    /* Calculate available data */
    if (info->tail > info->head)
        bytes_read = min(length, (size_t)(info->tail - info->head));
    else
        bytes_read = min(length, info->buffer_size - info->head);

    if (bytes_read == 0) {
        driver_stats.buffer_underflows++;
        mutex_unlock(&info->buffer_lock);
        return 0;
    }

    /* Copy data to user space */
    if (copy_to_user(buffer, info->device_buffer + info->head, bytes_read)) {
        mutex_unlock(&info->buffer_lock);
        return -EFAULT;
    }

    info->head = (info->head + bytes_read) % info->buffer_size;
    driver_stats.total_reads++;

    /* Update buffer info */
    info->last_read_time = ktime_get_real_seconds();
    info->last_read_pid = current->pid;
    info->last_read_owner = current_uid().val;

    mutex_unlock(&info->buffer_lock);

    /* Wake up writers */
    wake_up_interruptible(&write_queue);

    /* Notify asynchronous readers */
    if (info->fasync_queue)
        kill_fasync(&info->fasync_queue, SIGIO, POLL_IN);

    return bytes_read;
}

/* Device Write Function */
static ssize_t dev_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset)
{
    int minor = iminor(file->f_inode);
    dev_buf_info_t *info = &buffer_info[minor];
    ssize_t bytes_written = 0;

    if (minor >= MAX_DEVICES)
        return -ENODEV;

    mutex_lock(&info->buffer_lock);

    /* Handle blocking/non-blocking mode */
    while (((info->tail + 1) % info->buffer_size) == info->head) {
        if (!info->is_blocking) {
            mutex_unlock(&info->buffer_lock);
            return -EAGAIN;
        }
        mutex_unlock(&info->buffer_lock);
        if (wait_event_interruptible(write_queue, ((info->tail + 1) % info->buffer_size) != info->head))
            return -ERESTARTSYS;
        mutex_lock(&info->buffer_lock);
    }

    /* Calculate space available */
    if (info->head > info->tail)
        bytes_written = min(length, (size_t)(info->head - info->tail - 1));
    else
        bytes_written = min(length, (size_t)(info->buffer_size - info->tail - info->head - 1));

    if (bytes_written == 0) {
        driver_stats.buffer_overflows++;
        mutex_unlock(&info->buffer_lock);
        return -ENOMEM;
    }

    /* Copy data from user space */
    if (copy_from_user(info->device_buffer + info->tail, buffer, bytes_written)) {
        mutex_unlock(&info->buffer_lock);
        return -EFAULT;
    }

    info->tail = (info->tail + bytes_written) % info->buffer_size;
    driver_stats.total_writes++;

    /* Update buffer info */
    info->last_write_time = ktime_get_real_seconds();
    info->last_write_pid = current->pid;
    info->last_write_owner = current_uid().val;

    mutex_unlock(&info->buffer_lock);

    /* Wake up readers */
    wake_up_interruptible(&read_queue);

    /* Notify asynchronous readers */
    if (info->fasync_queue)
        kill_fasync(&info->fasync_queue, SIGIO, POLL_OUT);

    return bytes_written;
}

/* Device IOCTL Function */
/* Device IOCTL Function */
static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int minor = MINOR(file->f_inode->i_rdev);
    dev_buf_info_t *info = &buffer_info[minor];
    driver_stats_t stats;
    int new_size;

    if (minor >= MAX_DEVICES)
        return -ENODEV;

    switch (cmd) {
        case IOCTL_BLOCK:
            printk(KERN_INFO DRIVER_NAME ": Device %d: IOCTL_BLOCK\n", minor);
            info->is_blocking = 1;
            break;

        case IOCTL_NONBLOCK:
            printk(KERN_INFO DRIVER_NAME ": Device %d: IOCTL_NONBLOCK\n", minor);
            info->is_blocking = 0;
            break;

        case IOCTL_BUFINFO: {
            dev_buf_info_user_t user_info;

            /* Populate user_info with data from kernel-space info */
            user_info.last_read_time = ktime_to_ns(info->last_read_time);
            user_info.last_write_time = ktime_to_ns(info->last_write_time);
            user_info.last_read_pid = info->last_read_pid;
            user_info.last_write_pid = info->last_write_pid;
            user_info.last_read_owner = info->last_read_owner;
            user_info.last_write_owner = info->last_write_owner;
            user_info.head = info->head;
            user_info.tail = info->tail;
            user_info.total_reads = info->total_reads;
            user_info.total_writes = info->total_writes;

            /* Copy to user space */
            if (copy_to_user((dev_buf_info_user_t __user *)arg, &user_info, sizeof(user_info))) {
                printk(KERN_ERR DRIVER_NAME ": Device %d: Failed to copy buffer info to user space\n", minor);
                return -EFAULT;
            }
            break;
        }

        case IOCTL_SET_BUFFER_SIZE:
            printk(KERN_INFO DRIVER_NAME ": Device %d: IOCTL_SET_BUFFER_SIZE\n", minor);
            if (copy_from_user(&new_size, (int __user *)arg, sizeof(int))) {
                printk(KERN_ERR DRIVER_NAME ": Device %d: Failed to copy new buffer size from user space\n", minor);
                return -EFAULT;
            }
            if (new_size <= 0) {
                printk(KERN_ERR DRIVER_NAME ": Device %d: Invalid buffer size %d\n", minor, new_size);
                return -EINVAL;
            }
            mutex_lock(&info->buffer_lock);
            kfree(info->device_buffer);
            info->device_buffer = kmalloc(new_size, GFP_KERNEL);
            if (!info->device_buffer) {
                mutex_unlock(&info->buffer_lock);
                return -ENOMEM;
            }
            info->buffer_size = new_size;
            memset(info->device_buffer, 0, info->buffer_size);
            mutex_unlock(&info->buffer_lock);
            printk(KERN_INFO DRIVER_NAME ": Device %d: Buffer size set to %d\n", minor, new_size);
            break;

        case IOCTL_GET_STATS: {
            driver_stats_user_t user_stats;

            /* Populate user_stats with data from kernel-space stats */
            user_stats.total_reads = driver_stats.total_reads;
            user_stats.total_writes = driver_stats.total_writes;
            user_stats.buffer_overflows = driver_stats.buffer_overflows;
            user_stats.buffer_underflows = driver_stats.buffer_underflows;

            /* Copy to user space */
            if (copy_to_user((driver_stats_user_t __user *)arg, &user_stats, sizeof(user_stats))) {
                printk(KERN_ERR DRIVER_NAME ": Device %d: Failed to copy stats to user space\n", minor);
                return -EFAULT;
            }
            break;
        }

        default:
            printk(KERN_ERR DRIVER_NAME ": Device %d: Incorrect IOCTL command %u\n", minor, cmd);
            return -EINVAL;
    }

    return 0;
}



/* Device MMAP Function */
static int dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int minor = iminor(filp->f_inode);
    unsigned long size = vma->vm_end - vma->vm_start;
    dev_buf_info_t *info;

    if (minor >= MAX_DEVICES)
        return -ENODEV;

    info = &buffer_info[minor];

    if (size > info->buffer_size)
        return -EINVAL;

    if (remap_pfn_range(vma, vma->vm_start, virt_to_phys(info->device_buffer) >> PAGE_SHIFT,
                        size, vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}

/* Device Fasync Function */
static int dev_fasync(int fd, struct file *filp, int mode)
{
    int minor = iminor(filp->f_inode);
    dev_buf_info_t *info = &buffer_info[minor];

    if (minor >= MAX_DEVICES)
        return -ENODEV;

    return fasync_helper(fd, filp, mode, &info->fasync_queue);
}

/* Device Poll Function */
static unsigned int dev_poll(struct file *file, poll_table *wait)
{
    unsigned int mask = 0;
    int minor = iminor(file->f_inode);
    dev_buf_info_t *info = &buffer_info[minor];

    if (minor >= MAX_DEVICES)
        return POLLERR;

    poll_wait(file, &read_queue, wait);
    poll_wait(file, &write_queue, wait);

    mutex_lock(&info->buffer_lock);

    if (info->head != info->tail)
        mask |= POLLIN | POLLRDNORM;

    if (((info->tail + 1) % info->buffer_size) != info->head)
        mask |= POLLOUT | POLLWRNORM;

    mutex_unlock(&info->buffer_lock);

    return mask;
}

/* Power Management Suspend Function */
static int dev_suspend(struct device *dev)
{
    printk(KERN_INFO DRIVER_NAME ": Device suspended\n");
    return 0;
}

/* Power Management Resume Function */
static int dev_resume(struct device *dev)
{
    printk(KERN_INFO DRIVER_NAME ": Device resumed\n");
    return 0;
}

/* Driver Initialization Function */
static int __init linux_driver_init(void)
{
    int ret, i;
    printk(KERN_INFO DRIVER_NAME ": Initializing driver\n");

    /* Initialize global mutex */
    mutex_init(&global_lock);

    /* Allocate major and minor numbers for multiple devices */
    ret = alloc_chrdev_region(&dev_number, 0, MAX_DEVICES, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR DRIVER_NAME ": Failed to allocate device numbers\n");
        return ret;
    }

    major_number = MAJOR(dev_number);
    printk(KERN_INFO DRIVER_NAME ": Allocated major number %d\n", major_number);

    /* Initialize device class */
    dev_class = class_create(DEVICE_CLASS_NAME);
    if (IS_ERR(dev_class)) {
        unregister_chrdev_region(dev_number, MAX_DEVICES);
        printk(KERN_ERR DRIVER_NAME ": Failed to create device class\n");
        return PTR_ERR(dev_class);
    }

    /* Initialize and add devices */
    for (i = 0; i < MAX_DEVICES; i++) {
        cdev_init(&char_device[i], &fops);
        char_device[i].owner = THIS_MODULE;
        ret = cdev_add(&char_device[i], MKDEV(major_number, i), 1);
        if (ret) {
            printk(KERN_ERR DRIVER_NAME ": Failed to add cdev for device %d\n", i);
            /* Cleanup previously added devices */
            while (--i >= 0)
                cdev_del(&char_device[i]);
            class_destroy(dev_class);
            unregister_chrdev_region(dev_number, MAX_DEVICES);
            return ret;
        }

        /* Create device node with numeric suffix */
        device_instance[i] = device_create(dev_class, NULL, MKDEV(major_number, i), NULL, DEVICE_NAME "%d", i);
        if (IS_ERR(device_instance[i])) {
            printk(KERN_ERR DRIVER_NAME ": Failed to create device %d\n", i);
            /* Cleanup */
            while (--i >= 0) {
                device_destroy(dev_class, MKDEV(major_number, i));
                cdev_del(&char_device[i]);
            }
            class_destroy(dev_class);
            unregister_chrdev_region(dev_number, MAX_DEVICES);
            return PTR_ERR(device_instance[i]);
        }

        /* Create sysfs attribute */
        ret = device_create_file(device_instance[i], &dev_attr_buffer_size);
        if (ret) {
            printk(KERN_ERR DRIVER_NAME ": Failed to create sysfs attribute for device %d\n", i);
            device_destroy(dev_class, MKDEV(major_number, i));
            cdev_del(&char_device[i]);
            class_destroy(dev_class);
            unregister_chrdev_region(dev_number, MAX_DEVICES);
            return ret;
        }

        /* Initialize buffer info */
        mutex_init(&buffer_info[i].buffer_lock);
        buffer_info[i].head = buffer_info[i].tail = 0;
        buffer_info[i].last_read_time = 0;
        buffer_info[i].last_write_time = 0;
        buffer_info[i].last_read_pid = 0;
        buffer_info[i].last_write_pid = 0;
        buffer_info[i].last_read_owner = 0;
        buffer_info[i].last_write_owner = 0;
        buffer_info[i].fasync_queue = NULL;
        buffer_info[i].total_reads = 0;
        buffer_info[i].total_writes = 0;
        buffer_info[i].is_blocking = 1; /* Default to blocking mode */

        /* Allocate device buffer */
        buffer_info[i].device_buffer = kmalloc(buffer_size, GFP_KERNEL);
        if (!buffer_info[i].device_buffer) {
            printk(KERN_ERR DRIVER_NAME ": Failed to allocate memory for device buffer %d\n", i);
            device_remove_file(device_instance[i], &dev_attr_buffer_size);
            device_destroy(dev_class, MKDEV(major_number, i));
            cdev_del(&char_device[i]);
            class_destroy(dev_class);
            unregister_chrdev_region(dev_number, MAX_DEVICES);
            return -ENOMEM;
        }
        memset(buffer_info[i].device_buffer, 0, buffer_size);
        buffer_info[i].buffer_size = buffer_size;
    }

    /* Create debugfs directory */
    debugfs_dir = debugfs_create_dir(DRIVER_NAME, NULL);
    if (!debugfs_dir) {
        printk(KERN_ERR DRIVER_NAME ": Failed to create debugfs directory\n");
        linux_driver_exit();
        return -ENOMEM;
    }

    /* Create debugfs stats file */
    debugfs_stats = debugfs_create_file("stats", 0444, debugfs_dir, NULL, &debugfs_fops);
    if (!debugfs_stats) {
        printk(KERN_ERR DRIVER_NAME ": Failed to create debugfs stats file\n");
        linux_driver_exit();
        return -ENOMEM;
    }

    /* Start kernel thread */
    kthread_task = kthread_run(kernel_thread_func, NULL, "linux_driver_kthread");
    if (IS_ERR(kthread_task)) {
        printk(KERN_ERR DRIVER_NAME ": Failed to create kernel thread\n");
        linux_driver_exit();
        return PTR_ERR(kthread_task);
    }

    printk(KERN_INFO DRIVER_NAME ": Driver initialized successfully\n");
    return 0;
}

/* Driver Exit Function */
static void __exit linux_driver_exit(void)
{
    int i;

    /* Stop kernel thread */
    if (kthread_task)
        kthread_stop(kthread_task);

    /* Remove debugfs entries */
    if (debugfs_stats)
        debugfs_remove(debugfs_stats);
    if (debugfs_dir)
        debugfs_remove(debugfs_dir);

    /* Remove devices */
    for (i = 0; i < MAX_DEVICES; i++) {
        if (device_instance[i]) {
            device_remove_file(device_instance[i], &dev_attr_buffer_size);
            device_destroy(dev_class, MKDEV(major_number, i));
        }
        cdev_del(&char_device[i]);
        if (buffer_info[i].device_buffer)
            kfree(buffer_info[i].device_buffer);
    }

    /* Destroy device class */
    if (dev_class)
        class_destroy(dev_class);

    /* Unregister device numbers */
    unregister_chrdev_region(dev_number, MAX_DEVICES);

    printk(KERN_INFO DRIVER_NAME ": Driver exited successfully\n");
}

/* Module Initialization and Exit Registration */
module_init(linux_driver_init);
module_exit(linux_driver_exit);

