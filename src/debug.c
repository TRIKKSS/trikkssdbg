#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "debug.h"
#include "utils.h"
#include "decode_opcodes.h"

/*
	don't take care about my comments, my english is bad.
*/

bp* breakpoints = NULL;

int add_breakpoint(
	bp** breakpoint,
	int id,
	long int instruction,
	long int address,
	char* description
)
{

	// will add a new breakpoint and return its ID
	// recursive function thanks Mr François :)

	if(*breakpoint == NULL)
	{
		*breakpoint = (bp*)malloc(sizeof(bp));
		check_for_malloc_errors(*breakpoint);

		char* desc;
		// if a description was entered by a user
		// allocate memory and copy it.
		if (description != NULL)
		{
			desc = malloc(strlen(description) + 1);
			check_for_malloc_errors(description);
			strcpy(desc, description);
		} else {
			desc = NULL;
		}

		(*breakpoint)->id = id;
		(*breakpoint)->description = desc;
		(*breakpoint)->address = address;
		(*breakpoint)->instruction_before = instruction;
		(*breakpoint)->next_node = NULL;

		return id;	
	}

	return add_breakpoint(
		&((*breakpoint)->next_node),
		(*breakpoint)->id + 1,
		instruction,
		address,
		description
	);
}

void delete_breakpoint(int id)
{
	// change next node address
	// free description
	// free the bp structure
	// todo : replace breakpoint by previous instruction in memory

	bp* a = breakpoints;
	bp* previous_bp_tmp = NULL;
	bool id_found = false;

	while(a!=NULL)
	{
		if (a->id == id)
		{
			id_found = true;
			break;
		}

		previous_bp_tmp = a;
		a = a->next_node;
	}

	if (id_found == false)
	{
		printf("[-] error. Breakpoint with id %d not found.\n", id);
		return;
	}

	if (previous_bp_tmp == NULL)
	{

		// if it is the first bp
		// just change the breakpoint address to the next struct and free it.
		breakpoints = a->next_node;
		if (a->description != NULL)
		{
			free(a->description);
		}
		free(a);

	} else {
		// change next node address 
		previous_bp_tmp->next_node = a->next_node;

		if (a->description != NULL)
		{
			free(a->description);
		}
		free(a);
	}
}

bool bp_already_exist(long int addr)
{
	// check if a breakpoint has already been defined.
	bp* a = breakpoints;
	while(a != NULL)
	{
		if (a->address == addr)
		{
			return true;
		}
		a = a->next_node;
	}
	return false;
}

void print_all_bp()
{
	if (breakpoints == NULL)
	{
		printf("[-] no breakpoint defined.\n");
		return;
	}
	bp* a = breakpoints;

	do
	{
		printf("[~] breakpoint n°%d at %p ", a->id, a->address);
		if (a->description != NULL)
		{
			printf("[bp description : %s]", a->description);
		}
		a = a->next_node;
		printf("\n");
	} while (a != NULL);
}


long get_register(pid_t process, char* reg_name)
{
	struct user_regs_struct registers;
	ptrace(PTRACE_GETREGS, process, NULL, &registers);

	if (strcmp(reg_name,"r15") == 0)
	{
		return registers.r15;
	}
	if (strcmp(reg_name,"r14") == 0)
	{
		return registers.r14;
	}
	if (strcmp(reg_name,"r13") == 0)
	{
		return registers.r13;
	}
	if (strcmp(reg_name,"r12") == 0)
	{
		return registers.r12;
	}
	if (strcmp(reg_name,"rbp") == 0)
	{
		return registers.rbp;
	}
	if (strcmp(reg_name,"rbx") == 0)
	{
		return registers.rbx;
	}
	if (strcmp(reg_name,"r11") == 0)
	{
		return registers.r11;
	}
	if (strcmp(reg_name,"r10") == 0)
	{
		return registers.r10;
	}
	if (strcmp(reg_name,"r9") == 0)
	{
		return registers.r9;
	}
	if (strcmp(reg_name,"r8") == 0)
	{
		return registers.r8;
	}
	if (strcmp(reg_name,"rax") == 0)
	{
		return registers.rax;
	}
	if (strcmp(reg_name,"rcx") == 0)
	{
		return registers.rcx;
	}
	if (strcmp(reg_name,"rdx") == 0)
	{
		return registers.rdx;
	}
	if (strcmp(reg_name,"rsi") == 0)
	{
		return registers.rsi;
	}
	if (strcmp(reg_name,"rdi") == 0)
	{
		return registers.rdi;
	}
	if (strcmp(reg_name,"orig_rax") == 0)
	{
		return registers.orig_rax;
	}
	if (strcmp(reg_name,"rip") == 0)
	{
		return registers.rip;
	}
	if (strcmp(reg_name,"cs") == 0)
	{
		return registers.cs;
	}
	if (strcmp(reg_name,"eflags") == 0)
	{
		return registers.eflags;
	}
	if (strcmp(reg_name,"rsp") == 0)
	{
		return registers.rsp;
	}
	if (strcmp(reg_name,"ss") == 0)
	{
		return registers.ss;
	}
	if (strcmp(reg_name,"fs_base") == 0)
	{
		return registers.fs_base;
	}
	if (strcmp(reg_name,"gs_base") == 0)
	{
		return registers.gs_base;
	}
	if (strcmp(reg_name,"ds") == 0)
	{
		return registers.ds;
	}
	if (strcmp(reg_name,"es") == 0)
	{
		return registers.es;
	}
	if (strcmp(reg_name,"fs") == 0)
	{
		return registers.fs;
	}
	if (strcmp(reg_name,"gs") == 0)
	{
		return registers.gs;
	}

	return 0;

}

void print_all_registers(pid_t process)
{
	// todo : parse eflags

	struct user_regs_struct registers;
	ptrace(PTRACE_GETREGS, process, NULL, &registers);
 
	printf("r15\t\t%p\n", registers.r15);
	printf("r14\t\t%p\n", registers.r14);
	printf("r13\t\t%p\n", registers.r13);
	printf("r12\t\t%p\n", registers.r12);
	printf("r11\t\t%p\n", registers.r11);
	printf("r10\t\t%p\n", registers.r10);
	printf("r9\t\t%p\n", registers.r9);
	printf("r8\t\t%p\n", registers.r8);
	printf("rbp\t\t%p\n", registers.rbp);
	printf("rbx\t\t%p\n", registers.rbx);
	printf("rax\t\t%p\n", registers.rax);
	printf("rcx\t\t%p\n", registers.rcx);
	printf("rdx\t\t%p\n", registers.rdx);
	printf("rsi\t\t%p\n", registers.rsi);
	printf("rdi\t\t%p\n", registers.rdi);
	printf("rip\t\t%p\n", registers.rip);
	printf("cs\t\t%p\n", registers.cs);
	printf("eflags\t\t%p\n", registers.eflags);
	printf("rsp\t\t%p\n", registers.rsp);
	printf("ss\t\t%p\n", registers.ss);
	printf("fs_base\t\t%p\n", registers.fs_base);
	printf("gs_base\t\t%p\n", registers.gs_base);
	printf("ds\t\t%p\n", registers.ds);
	printf("es\t\t%p\n", registers.es);
	printf("fs\t\t%p\n", registers.fs);
	printf("gs\t\t%p\n", registers.gs);
}

bp* is_user_breakpoint(long rip)
{
	// check if there is a breakpoint at this address.
	// if yes : return address
	// if not : return NULL
	bp* a = breakpoints;
	while (a != NULL)
	{
		if (a->address == rip) {
			return a;
		}
		a = a->next_node;
	}
	return NULL;
}

void debugger_cli(pid_t child)
{
	while(1)
	{			

		int wait_status;
	
		pid_t signal = waitpid(child, &wait_status,0);

		/*
		if(WIFEXITED(wait_status)) {
			printf("Exit status %d\n", WEXITSTATUS(wait_status));
			return;
		} else if(WIFSIGNALED(wait_status)) {
			printf("Terminated by signal %d (%s)%s\n",
			WTERMSIG(wait_status),
			strsignal(WTERMSIG(wait_status)),
			WCOREDUMP(wait_status)?" (core dumped)":"");
			return;
		} else if(WIFSTOPPED(wait_status)) {
			printf("Stopped by signal %d (%s)\n",
			WSTOPSIG(wait_status),
			strsignal(WSTOPSIG(wait_status)));
			return;
		}
		*/

		if (signal == -1)
		{
			printf("[~] Process ended.\n");
			return;
		}

		if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGSEGV)
		{
			printf("[-] child stopped by SIGSEGV at 0x%lx.\n", get_register(child, "rip"));
			return;
		}

		if (WIFSTOPPED(wait_status))
		{
			if (WSTOPSIG(wait_status) == SIGSEGV)
			{
				printf("[-] child stopped by SIGSEGV at 0x%lx.\n", get_register(child, "rip"));
				return;
			}
			if (WSTOPSIG(wait_status) != SIGTRAP)
			{
				printf("Stopped by signal %d at 0x%lx (%s)\n",
				WSTOPSIG(wait_status),
				get_register(child, "rip"),
				strsignal(WSTOPSIG(wait_status)));
				return;
			}
			printf("| sigtrap at %p |\n", get_register(child, "rip")-1);

			while(1)
			{
				// getting user input.
				char user_input[4096];
				printf(">>>");
				fgets(user_input, sizeof(user_input), stdin);
				user_input[strcspn(user_input, "\n")] = 0;
				// splitting user input using strtok.
				char *command = strtok(user_input, " ");
				
				if (command == NULL)
				{
					continue;
				}

				if (strcmp(command, "reg") == 0) {
					// reg command. 
					// used to print registers value.
					
					char* reg_name = strtok(NULL, " ");

					if (reg_name == NULL)
					{
						// if no register specified print all regs
						print_all_registers(child);
					} else if (!is_reg_available(reg_name))
					{
						printf("[-] not a valid register.\n");
					} else {
						// print a special register.
						printf("%s = %p\n", reg_name, get_register(child, reg_name));
					}
				}

				if (strcmp(command, "bp") == 0) {
					// reg command. 
					// used to print registers value.
					
					char* str_bp_addr = strtok(NULL, " ");
					
					if (str_bp_addr == NULL)
					{
						print_all_bp();
					} else {
						long int bp_addr = strtol(str_bp_addr, NULL, 0);

						char* description = strtok(NULL, " ");
						if (bp_already_exist(bp_addr))
						{
							printf("[-] breakpoint already exist.\n");
						}
						else if(!place_breakpoint(child, bp_addr, description))
						{
							printf("[-] error. Can't break at 0x%lx\n", bp_addr);
						} else {
							printf("[+] breakpoint defined at 0x%lx\n", bp_addr);
						}
						

						// add_breakpoint(bp_addr, 0xcafebabe, description);
						// place_breakpoint(child, bp_addr);
						// printf("%s\n", breakpoints->description);
					}
				}

				if (strcmp(command, "del") == 0) {
					char* str_id = strtok(NULL, " ");
					if (str_id == NULL)
					{
						printf("[-] error. You have to specify an ID.\n");
					} else {
						int id = (int)strtol(str_id, NULL, 0);
						remove_breakpoint(child, id);
					}
				}

				if (strcmp(command, "disas") == 0)
				{
					char* str_addr = strtok(NULL, " ");
					char* str_size = strtok(NULL, " ");

					if (str_addr && str_size)
					{
						long int addr = strtol(str_addr, NULL, 0);
						int size = strtol(str_size, NULL, 0);
						printf("[+] reading %d bytes at %p\n", size, addr);
						uint8_t* asm_code = read_memory(child, addr, size);
						decode_x64(asm_code, size, addr);
						free(asm_code);
					} else {
						printf("[-] invalid address or invalid size.\n");
					}
				}

				if (strcmp(command, "read") == 0)
				{
					char* str_addr = strtok(NULL, " ");
					char* str_size = strtok(NULL, " ");
					if (str_addr && str_size)
					{
						long int addr = strtol(str_addr, NULL, 0);
						int size = strtol(str_size, NULL, 0);
						printf("[+] reading %d bytes at %p\n", size, addr);
						uint8_t* data = read_memory(child, addr, size);
						for(int i=0; i < size; i++)
						{
							printf("\\x%02x", data[i]);
						}
						printf("\n");
						free(data);
					} else {
						printf("[-] invalid address or memory size.\n");
					}
				}


				if (strcmp(command, "continue") == 0) {
					bp* actual_bp = is_user_breakpoint(get_register(child, "rip")-1);
					if (actual_bp)
					{
					
						// save registers and change rip address
						struct user_regs_struct registers;
						ptrace(PTRACE_GETREGS, child, NULL, &registers);
						registers.rip = actual_bp->address;
						//if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) == -1)
						//{
						//	perror("singlestep error");
						//}
						// single step forward
						// ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
						
						// remove breakpoint
						if(ptrace(PTRACE_POKETEXT, child, actual_bp->address, actual_bp->instruction_before) < 0)
						{
							perror("[-] Error");
							// printf("[-] An error as occured.\n");
							exit(1);
						}

						// set regs saved with rip changed.
						ptrace(PTRACE_SETREGS, child, NULL, &registers);						
						
						if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) == -1)
						{
							perror("singlestep error");
						}
						waitpid(child, &wait_status, 0);
						
						// set the breakpoint again.
						if(ptrace(PTRACE_POKETEXT, child, actual_bp->address, (actual_bp->instruction_before & ~0xff) | 0xcc) < 0)
						{
							perror("Error bp : ");
							exit(1);
						}
					}
					break;
				}

				if (strcmp(command, "help") == 0) {
					help();
				}

				if (strcmp(command, "exit") == 0) {
					// kill child process
					kill(child,SIGKILL);
					printf("[+] child process killed.\n[+] good bye.\n");
					return;
				}
			}
		}
		ptrace(PTRACE_CONT, child, NULL, NULL);
	}
}

bool place_breakpoint(pid_t child, long int address, char* description)
{
	// return false if there is an error.

	// we have to place the breakpoint 1 byte before the instruction we want.
	long int instruction = ptrace(PTRACE_PEEKTEXT, child, address, NULL);
	
	if (instruction == -1)
	{
		// printf("instruction is %lx\n", instruction);
		return false;
	}

	// will replace the least significant byte by 0xcc (sigtrap)
	// example : instruction = 0xffffffff -> 0xffffffcc
	// (instruction & ~0xff) | 0xcc

	if(ptrace(PTRACE_POKETEXT, child, address, 0x90909090909090cc) < 0)
	{
		return false;
	}

	add_breakpoint(
		&breakpoints,
		1,
		instruction,
		address,
		description
	);
	return true;

}

void remove_breakpoint(pid_t child, int id)
{
	// todo.
	// segfault when invalid instruction is the first breakpoint (id 1)
	bp* a = breakpoints;
	while(a != NULL)
	{
		if (a->id == id) {
			printf("before : 0x%lx\n", ptrace(PTRACE_PEEKTEXT, child, a->address, NULL));
			if(ptrace(PTRACE_POKETEXT, child, a->address, a->instruction_before) < 0)
			{
				printf("[-] error. can't remove breakpoint %d", id);
			}
			printf("after : 0x%lx\n", ptrace(PTRACE_PEEKTEXT, child, a->address, NULL));
			delete_breakpoint(id);
			printf("breakpoint removed.\n");
			return;
		}
		a = a->next_node;
	}
	printf("[-] error. breakpoint not found.\n");
}

uint8_t* read_memory(pid_t child, long int addr, int size)
{
	uint8_t* memory = malloc(size);

	for (int i=0; i < size; i++)
	{
		long int data = ptrace(PTRACE_PEEKTEXT, child, addr+i, NULL);
		
		if(data == -1) {
			perror("[-] Error");
		} else {
			memory[i] = data & 0xff;
		}
	}

	return memory;
}