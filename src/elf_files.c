#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <dlfcn.h> 
#include <string.h>

// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header²

// extern void* _start;

unsigned long get_base_address(pid_t child)
{
	unsigned long base_addr;
	FILE* fp;

	char cmd[50];
	sprintf(cmd, "/proc/%d/maps", child);

    fp = fopen(cmd, "r");
    if (fp == NULL) {
        printf("Error: failed to open /proc/pid/maps.\n");
        exit(EXIT_FAILURE);
    }
	fscanf(fp, "%lx-", &base_addr);
	
	// printf("base_address : %lx\n", base_addr);

	return base_addr;
}

unsigned long get_entry_point(FILE* elf_fd, pid_t child)
{
	// reading 8 bytes at offset 0x18 (= entrypoint)

	unsigned long entry_point;

	fseek(elf_fd, 0x18, SEEK_SET);
	
	if (fread(&entry_point, 8, 1, elf_fd) != 1) // , 1, 8, elf_fd) == -1)
	{
		perror("Getting get_entry_point ");
		exit(1);
	}

	unsigned long base_addr = get_base_address(child);
	// printf("base addr is : %p\n", base_addr);
	// printf("entry point is : %p\n", entry_point);
	// printf("base addr + entrypoint offset : %p\n", base_addr + entry_point);
	return (unsigned long)(base_addr + entry_point); // result;
}

bool is_correct_elf(FILE* elf_fd)
{
	fseek(elf_fd, 0, 0);

	// check magic bytes
	unsigned int magic_bytes;

	if (fread(&magic_bytes, 4, 1, elf_fd) != 1)
	{
		perror("Error while reading file");
		exit(1);
	}

	if (magic_bytes != 0x464c457f)
	{
		fprintf(stderr, "Not a valid elf, wrong magic bytes.\n");
		return false;
	}

	// check 64 bit format
	unsigned char arch;
	if (fread(&arch, 1, 1, elf_fd) != 1)
	{
		perror("Error while read file");
		exit(1);
	}

	if (arch != '\x02')
	{
		fprintf(stderr, "wrong format, this is a 64 bits elf debugger.");
		return false;
	}

	return true;
}

void print_proc_maps(pid_t child)
{
	char cmd[50];
	sprintf(cmd, "/proc/%d/maps", child);
	FILE* mem_maps_fd = fopen(cmd, "r");
	if (mem_maps_fd == NULL) {
	    perror("Error while reading /proc/pid/maps");
	    exit(1);
    }
	char c;
	while ((c = fgetc(mem_maps_fd)) != EOF) {
		printf("%c", c);
	}
	fclose(mem_maps_fd);
}