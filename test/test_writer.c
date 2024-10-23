/* TEST WRITER */

#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#define BASE_DEVICE_NAME "/dev/test_task_dev"
#define BUFFER_SIZE 1024
#define MAX_DEVICES 4  /* Should match the driver's MAX_DEVICES */

/* Define User-Space Structures */
typedef struct {
    long long last_read_time;  /* Changed from long to long long for nanosecond precision */
    long long last_write_time; /* Changed from long to long long for nanosecond precision */
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

/* Define IOCTL Commands */
#define IOCTL_BLOCK            _IO('k', 0)
#define IOCTL_NONBLOCK         _IO('k', 1)
#define IOCTL_BUFINFO          _IOR('k', 2, dev_buf_info_user_t)
#define IOCTL_SET_BUFFER_SIZE  _IOW('k', 3, int)
#define IOCTL_GET_STATS        _IOR('k', 4, driver_stats_user_t)

/** @brief Display list of available commands. */
static void help(void);

/* Function to set blocking/non-blocking mode */
static void set_mode(int fd, unsigned long cmd) {
    if (ioctl(fd, cmd, NULL) == -1) {
        perror("ioctl set_mode");
        exit(EXIT_FAILURE);
    }
}

/* Function to display buffer information */
static void display_buf_info(dev_buf_info_user_t info) {
    printf("Buffer Info:\n");
    printf("Last Read Time: %lld ns\n", info.last_read_time);
    printf("Last Write Time: %lld ns\n", info.last_write_time);
    printf("Last Read PID: %d\n", info.last_read_pid);
    printf("Last Write PID: %d\n", info.last_write_pid);
    printf("Last Read Owner UID: %d\n", info.last_read_owner);
    printf("Last Write Owner UID: %d\n", info.last_write_owner);
    printf("Head: %zu\n", info.head);
    printf("Tail: %zu\n", info.tail);
    printf("Total Reads: %zu\n", info.total_reads);
    printf("Total Writes: %zu\n", info.total_writes);
}

int main(int argc, char **argv)
{
    char device_path[64];
    char buffer[BUFFER_SIZE] = "Message from writer";
    dev_buf_info_user_t info;
    int fd, ret, device_num;
    unsigned long ioctl_cmd = IOCTL_BLOCK;

    /* Handle incorrect number of arguments */
    if (argc < 2 || argc > 3) {
        help();
        exit(EXIT_FAILURE);
    }

    /* Parse device number */
    device_num = atoi(argv[1]);
    if (device_num < 0 || device_num >= MAX_DEVICES) {
        fprintf(stderr, "Invalid device number. Must be between 0 and %d.\n", MAX_DEVICES - 1);
        exit(EXIT_FAILURE);
    }

    snprintf(device_path, sizeof(device_path), "%s%d", BASE_DEVICE_NAME, device_num);

    fd = open(device_path, O_RDWR);
    if (fd == -1) {
        perror("Error opening device");
        exit(EXIT_FAILURE);
    }

    /* Select mode (IOCTL_BLOCK by default) */
    if (argc == 3) {
        if (strcmp(argv[2], "--nonblock") == 0)
            ioctl_cmd = IOCTL_NONBLOCK;
        else if (strcmp(argv[2], "--block") == 0)
            ioctl_cmd = IOCTL_BLOCK;
        else {
            help();
            close(fd);
            exit(EXIT_FAILURE);
        }
        set_mode(fd, ioctl_cmd);
    }

    printf("writer: Writing to %s: \"%s\"\n", device_path, buffer);
    ret = write(fd, buffer, strlen(buffer) + 1); // Write actual string length + null terminator

    if (ret == -1) {
        perror("write error");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Initialize the info structure before use
    memset(&info, 0, sizeof(info));

    if (ioctl(fd, IOCTL_BUFINFO, &info) == -1) {
        perror("ioctl IOCTL_BUFINFO");
        close(fd);
        exit(EXIT_FAILURE);
    }

    display_buf_info(info);

    close(fd);
    return 0;
}

static void help(void)
{
    puts("Usage: \t./writer <device_number> [argument]\n"
         "\n\t<device_number> \t - Specify the device number to write to (e.g., 0 for /dev/test_task_dev0).\n"
         "\n\t--nonblock  \t - Test non-blocking mode of read/write operations.\n"
         "\n\t--block     \t - Test blocking mode of read/write operations (default).\n");
}

