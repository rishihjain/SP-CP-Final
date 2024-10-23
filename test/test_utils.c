#include <time.h>

#include "test.h"

void set_mode(int fd, int mode, dev_buf_info_t *arg)
{
    int ret;

    switch (mode) {
        case IOCTL_BLOCK:
            puts("set mode: IOCTL_BLOCK");
            break;
        
        case IOCTL_NONBLOCK:
            puts("set mode: IOCTL_NONBLOCK");
            break;
        
        case IOCTL_BUFINFO:
            puts("set mode: IOCTL_BUFINFO");
            break;
    
        default:
            printf("incorrect mode: %d\n", mode);
            exit(EXIT_FAILURE);
            break;
    }

    ret = ioctl(fd, mode, arg);

    if (ret < 0) {
        perror("set ioctl mode error");
        exit(EXIT_FAILURE);
    }
}

void display_time(const char *descr, time_t raw_time)
{
    struct tm *tm;
    
    tm = localtime(&raw_time);
    
    printf("%s %02d-%02d-%d %02d:%02d:%02d\n", descr,
           tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900,
           tm->tm_hour, tm->tm_min,     tm->tm_sec);
}

void display_buf_info(dev_buf_info_t info)
{
    display_time("last read time: ",  info.last_read_time);
    display_time("last write time:", info.last_write_time);
    printf("last read PID:        %d\n", info.last_read_pid);
    printf("last write PID:       %d\n", info.last_write_pid);
    printf("last read owner UID:  %d\n", info.last_read_owner);
    printf("last write owner UID: %d\n", info.last_write_owner);
}