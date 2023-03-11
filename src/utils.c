#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"

char* available_regs[] = {"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"};

void check_for_malloc_errors(void* ptr)
{
	if (ptr == NULL)
	{
		printf("failed to allocate memory.");
		_exit(1);
	}
}

int is_reg_available(char *regs_name)
{
	for (int i = 0; available_regs[i] != NULL; i++)
	{
		if (strcmp(regs_name, available_regs[i]) == 0)
		{
			return 1;
		}
	}
	return 0;
}

void help()
{
	char help[] = "bp address [description] : place a breakpoint at address.\n"
		   "                           whitout arguments the bp command\n"
		   "                           will print all defined breakpoints\n"
		   "del breakoint_id         : delete a breakpoint.\n"
		   "reg [register name]      : print registers value.\n"
		   "read address size        : read size bytes at address\n"
		   "disas address size       : disassemble memory at address\n"
		   "map                      : print /proc/pid/maps of child\n"
		   "continue                 : continue the binary execution\n"
		   "exit                     : exit the debugger and kill child process.\n"
		   "help                     : print this help\n";
	printf("%s", help);
}