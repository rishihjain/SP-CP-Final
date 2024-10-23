#ifndef _TEST_TASK_LINUX_DRIVER_TEST_H_
#define _TEST_TASK_LINUX_DRIVER_TEST_H_

#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

#define DEVICE_NAME "/dev/test_task_dev"
#define BUFFER_SIZE 20

#define IOCTL_BLOCK          0
#define IOCTL_NONBLOCK       1
#define IOCTL_BUFINFO        _IOR('k', 2, dev_buf_info_t)
#define IOCTL_INCORRECT_MODE 99

/**
 * @brief Device buffer information structure.
 * 
 * Contains information about the time the last operation was
 * read and written to the buffer, as well as the identifiers 
 * of the owners and processes that completed these operations.
 */
typedef struct {
    time_t last_read_time;
    time_t last_write_time;
    pid_t  last_read_pid;
    pid_t  last_write_pid;
    uid_t  last_read_owner;
    uid_t  last_write_owner;
} dev_buf_info_t;

/**
 * @brief Set ioctl mode.
 * 
 * @param [in] fd - given device file descriptor.
 * @param [in] mode - given IOCTL mode.
 * @param [out] arg -given IOCTL argument (device buffer info structure).
 */
void set_mode(int fd, int mode, dev_buf_info_t *arg);

/**
 * @brief Display buffer information.
 * 
 * @param [in] buffer_info - given device buffer info structure.
 */
void display_buf_info(dev_buf_info_t info);

/**
 * @brief Display raw time in date format 
 * 
 * Displaying format: YEAR-MONTH-DAY HOURS-MINUTES-SECONDS
 * 
 * @param [in] descr - given description string.
 * @param [in] raw_time - given raw_time.
 */
void display_time(const char *descr, time_t raw_time);

#endif /* _TEST_TASK_LINUX_DRIVER_TEST_H_ */ 