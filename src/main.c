#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include "debug.h"
#include "utils.h"
#include "elf_files.h"

void usage(char* debugger_name);

int main(int argc, char** argv)
{
	if(argc != 2)
	{
		usage(argv[0]);
		return 1;
	}
	if (access(argv[1], F_OK) != 0) {
		printf("[-] can't access this binary.\n");
		return 1;
	}

	pid_t child;
	child = fork();

	if (child == 0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
		{
			printf("PTRACE ERROR\n");
			return 1;
		}

		// todo : get entry point, and add a break on it.
		if(execl(argv[1], argv[1], NULL) < 0)
		{
			exit(1);
		};
	} else if(child == -1) {
		fprintf(stderr, "fork() failed.\n");
	} else {
		printf("\n -- Welcome on trikkssdbg :p -- \n\n");

		FILE* elf_file_fd = fopen(argv[1], "r");
		if (elf_file_fd == NULL) {
		    perror("Error while reading binary");
		    exit(1);
		}

		if (!is_correct_elf(elf_file_fd))
		{
			kill(child, SIGKILL);
			fclose(elf_file_fd);
			return 1;
		}

		fclose(elf_file_fd);

		debugger_cli(argv[1], child);
	}
	return 0;
}

void usage(char* debugger_name)
{
	printf("Usage : %s binary\n", debugger_name);
}

/*
	todo : 
		- add a strace function which will trace all syscalls
		- add a ltrace function which will trace all libc calls
		- break on the entrypoint at the beginning (ok)
		- description more than 1 word
*/

