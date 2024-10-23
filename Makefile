SRC_DIR     = src/
TEST_DIR    = test/
DRIVER_NAME = linux_driver
DRIVER      = $(SRC_DIR)$(DRIVER_NAME).ko

all: $(NAME)
	$(MAKE) -C $(SRC_DIR) all

clean:
	$(MAKE) -C $(SRC_DIR) clean

fclean: clean
	$(MAKE) -C $(SRC_DIR) fclean
	rm -f $(DRIVER)

re: clean all

init:
	sudo insmod $(DRIVER)
	sudo chmod 666 /dev/test_task_dev

deinit:
	sudo rmmod $(DRIVER_NAME)

make_test:
	$(MAKE) -C $(TEST_DIR) all

clean_test:
	$(MAKE) -C $(TEST_DIR) fclean