/* TEST READER */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#define BASE_DEVICE_NAME "/dev/test_task_dev"
#define BUFFER_SIZE 1024
#define MAX_DEVICES         4

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <device_number>\n", prog_name);
    fprintf(stderr, "Example: %s 0  # Reads from /dev/test_task_dev0\n", prog_name);
}

int main(int argc, char **argv)
{
    char device_path[64];
    char buffer[BUFFER_SIZE];
    int fd, ret, device_num;

    if (argc != 2) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

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

    printf("reader: Waiting to read from %s...\n", device_path);
    ret = read(fd, buffer, BUFFER_SIZE);

    if (ret == -1) {
        perror("read error");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("reader: Read %d bytes: \"%s\"\n", ret, buffer);

    close(fd);
    return 0;
}
