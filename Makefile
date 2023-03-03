CC := gcc
SRCS := $(shell find src/ -name *.c)

trikkssdbg:
	$(CC) $(SRCS) -no-pie -l capstone -o trikkssdbg
